// Command check-image-ca inventories PEM certificates without running the image.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const maxFile = 32 << 20
const limitations = "Public-key-based PEM/JKS inventory, not a runtime TLS test. JKS integrity is not authenticated. Does not inspect DER/NSS stores, non-PEM embedded roots, mounted files, or runtime trust/revocation policy. Node configuration is advisory only. No matches does not prove safety."

type finding struct {
	Path    string `json:"path"`
	Subject string `json:"subject"`
	SHA256  string `json:"sha256"`
	Reason  string `json:"reason"`
}
type report struct {
	GoBinaries   []goBinary `json:"go_binaries"`
	NodeDetected bool       `json:"node_detected"`
	NodePolicy   string     `json:"node_ca_policy,omitempty"`
	Image        string     `json:"image"`
	ImageID      string     `json:"image_id"`
	Status       string     `json:"status"`
	Certificates int        `json:"pem_certificates_scanned"`
	Findings     []finding  `json:"findings"`
	Errors       []string   `json:"errors"`
	Skipped      []string   `json:"oversized_files_not_scanned"`
	Limitations  string     `json:"limitations"`
}

func scan(r io.Reader) (report, error) {
	out := report{GoBinaries: []goBinary{}, Limitations: limitations, Findings: []finding{}, Errors: []string{}, Skipped: []string{}}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		visit := func(c *x509.Certificate) {
			out.Certificates++
			if reason := classify(c); reason != "" {
				hash := sha256.Sum256(c.Raw)
				out.Findings = append(out.Findings, finding{"/" + strings.TrimLeft(h.Name, "/"), c.Subject.String(), hex.EncodeToString(hash[:]), reason})
			}
		}
		br := bufio.NewReader(tr)
		magic, _ := br.Peek(4)
		if bytes.Equal(magic, []byte{0xfe, 0xed, 0xfe, 0xed}) || strings.HasSuffix(h.Name, "/java/cacerts") || strings.HasSuffix(h.Name, ".jks") {
			if h.Size > maxFile {
				out.Skipped = append(out.Skipped, h.Name)
				continue
			}
			data, e := io.ReadAll(br)
			if e != nil {
				return out, e
			}
			certs, e := parseJKS(data)
			if e != nil {
				out.Errors = append(out.Errors, h.Name+": "+e.Error())
			} else {
				for _, c := range certs {
					visit(c)
				}
			}
		} else if executableMagic(magic) {
			binary, e := scanExecutable(br, func(r io.Reader) error { return scanPEM(r, visit) })
			if e != nil {
				out.Errors = append(out.Errors, h.Name+": "+e.Error())
			}
			if binary != nil {
				binary.Path = "/" + strings.TrimLeft(h.Name, "/")
				out.GoBinaries = append(out.GoBinaries, *binary)
				if binary.Status == "unknown" {
					out.Errors = append(out.Errors, binary.Path+": unrecognized Go release: "+binary.Version)
				}
			}
		} else if e := scanPEM(br, visit); e != nil {
			out.Errors = append(out.Errors, h.Name+": "+e.Error())
		}
		if strings.HasSuffix(h.Name, "/bin/node") || h.Name == "node" {
			out.NodeDetected = true
		}
	}
	out.Status = "no-matching-pem-certificates"
	if out.Certificates == 0 || len(out.Errors) > 0 || len(out.Skipped) > 0 {
		out.Status = "inconclusive"
	}
	if len(out.Findings) > 0 || out.hasOldGo() {
		out.Status = "potential-exposure"
	}
	return out, nil
}

func docker(args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	var stderr strings.Builder
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(b)), nil
}
func resolveImage(image string, invoke func(...string) (string, error)) (string, error) {
	id, err := invoke("image", "inspect", "--format", "{{.Id}}", image)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "no such image:") {
		return id, err
	}
	fmt.Fprintf(os.Stderr, "Image %s not found locally; pulling...\n", image)
	if _, err := invoke("pull", image); err != nil {
		return "", err
	}
	return invoke("image", "inspect", "--format", "{{.Id}}", image)
}

func check(image string) (report, error) {
	id, err := resolveImage(image, docker)
	if err != nil {
		return report{}, err
	}
	container, err := docker("create", "--entrypoint", "/__ca_scan_never_executed__", id)
	if err != nil {
		return report{}, err
	}
	defer func() {
		if _, err := docker("rm", "-v", container); err != nil {
			fmt.Fprintln(os.Stderr, "Container cleanup failed:", err)
		}
	}()
	cmd := exec.Command("docker", "export", container)
	cmd.Stderr = os.Stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return report{}, err
	}
	if err = cmd.Start(); err != nil {
		return report{}, err
	}
	out, scanErr := scan(pipe)
	if scanErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if scanErr != nil {
		return out, scanErr
	}
	if waitErr != nil {
		return out, waitErr
	}
	if out.NodeDetected {
		config, e := docker("image", "inspect", "--format", "{{json .Config}}", id)
		if e != nil {
			return out, e
		}
		out.NodePolicy = nodePolicy(config)
		if out.NodePolicy != "system CA requested; runtime overrides remain possible" {
			out.Errors = append(out.Errors, "Node embedded CA trust is not verified: "+out.NodePolicy)
			if len(out.Findings) == 0 && !out.hasOldGo() {
				out.Status = "inconclusive"
			}
		}
	}
	out.Image, out.ImageID = image, id
	return out, nil
}
func run() int {
	asJSON := flag.Bool("json", false, "Output JSON")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: check-image-ca [-json] IMAGE\nRequires Docker; missing images are pulled automatically. Never starts the container.")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		return 2
	}
	out, err := check(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Check failed:", err)
		return 2
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else {
		fmt.Printf("%s: %s\nPEM/JKS certificates scanned: %d\n", out.Image, out.Status, out.Certificates)
		for _, f := range out.Findings {
			fmt.Printf("  %s: %s\n    %s\n    SHA256: %s\n", f.Path, f.Reason, f.Subject, f.SHA256)
		}
		for _, b := range out.GoBinaries {
			fmt.Printf("  %s: Go %s (%s)\n", b.Path, b.Version, b.Status)
		}
		for _, e := range out.Errors {
			fmt.Fprintln(os.Stderr, e)
		}
		for _, p := range out.Skipped {
			fmt.Fprintln(os.Stderr, "Not scanned (>32 MiB):", p)
		}
		if out.NodePolicy != "" {
			fmt.Println("Node:", out.NodePolicy)
		}
		fmt.Println(out.Limitations)
	}
	if len(out.Findings) > 0 || out.hasOldGo() {
		return 1
	}
	if out.Status == "inconclusive" {
		return 2
	}
	return 0
}
func main() { os.Exit(run()) }
