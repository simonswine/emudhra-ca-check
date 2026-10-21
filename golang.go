package main

import (
	"bytes"
	"debug/buildinfo"
	"go/version"
	"io"
	"os"
	"strings"
)

type goBinary struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Status  string `json:"status"`
}

func (r report) hasOldGo() bool {
	for _, b := range r.GoBinaries {
		if b.Status == "below-minimum" {
			return true
		}
	}
	return false
}

func goVersionStatus(v string) string {
	if !version.IsValid(v) || strings.Contains(v, "rc") || strings.Contains(v, "beta") || strings.Contains(v, "devel") {
		return "unknown"
	}
	baseline := "go1.26.10"
	if version.Lang(v) == "go1.27" {
		baseline = "go1.27.3"
	}
	if version.Compare(v, baseline) >= 0 {
		return "meets-minimum"
	}
	return "below-minimum"
}

// Recognize executable formats supported by debug/buildinfo, regardless of mode
// bits or filename. Spool to disk for random access without buffering binaries.
func executableMagic(b []byte) bool {
	for _, magic := range [][]byte{
		[]byte("\x7fELF"), []byte("MZ"),
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca},
		{0x01, 0xdf}, {0x01, 0xf7},
	} {
		if bytes.HasPrefix(b, magic) {
			return true
		}
	}
	return false
}

func scanExecutable(r io.Reader, scanPEMFile func(io.Reader) error) (*goBinary, error) {
	f, err := os.CreateTemp("", "ca-check-go-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	pemErr := scanPEMFile(io.TeeReader(r, f))
	info, err := buildinfo.Read(f)
	if err != nil {
		return nil, pemErr
	} // Most executables are not Go binaries.
	return &goBinary{Version: info.GoVersion, Status: goVersionStatus(info.GoVersion)}, pemErr
}
