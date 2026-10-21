package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
)

// Public key identities from https://emudhra.we-have-a-problem.com/roots.json
// and impacted-intermediates.json. Match reissues and cross-signs, not names.
var blockedKeys = map[string]string{
	"bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3": "AAA Certificate Services",
	"8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782": "emSign ECC Root CA - G3",
	"c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9": "emSign Root TLS CA - G3",
	"0a6c2b2ca5b364207954171987ac9d2178561569d8205457e77ca90c32ede282": "emSign Root CS CA - G3",
	"ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105": "EM DV TLS CA - G3B",
	"43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b": "EM OV TLS CA - G3B",
	"e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41": "EM EV TLS CA - G3B",
	"49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f": "EM DV TLS CA - G3C",
	"63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8": "EM OV TLS CA - G3C",
	"5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0": "EM EV TLS CA - G3C",
	"ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6": "EM OV CS CA - G3B",
	"92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30": "EM OV CS CA - G3C",
}

func classify(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	if name := blockedKeys[hex.EncodeToString(sum[:])]; name != "" {
		return "Incident public key: " + name
	}
	return ""
}

// Scan all bytes, retaining only a possible PEM block and a small marker tail.
func scanPEM(r io.Reader, visit func(*x509.Certificate)) error {
	const begin = "-----BEGIN "
	buf := make([]byte, 64<<10)
	var pending []byte
	var problem error
	for {
		n, err := r.Read(buf)
		pending = append(pending, buf[:n]...)
		for {
			start := bytes.Index(pending, []byte(begin))
			if start < 0 {
				if len(pending) > len(begin) {
					pending = pending[len(pending)-len(begin):]
				}
				break
			}
			pending = pending[start:]
			end := bytes.Index(pending, []byte("-----END "))
			if end < 0 {
				if len(pending) > maxFile {
					problem = fmt.Errorf("oversized PEM block")
					pending = nil
				}
				break
			}
			tail := bytes.Index(pending[end+9:], []byte("-----"))
			if tail < 0 {
				if len(pending) > maxFile {
					problem = fmt.Errorf("oversized PEM block")
					pending = nil
				}
				break
			}
			stop := end + 9 + tail + 5
			if stop > maxFile {
				problem = fmt.Errorf("oversized PEM block")
				pending = pending[stop:]
				continue
			}
			block, _ := pem.Decode(pending[:stop])
			if block == nil {
				problem = fmt.Errorf("malformed PEM")
			} else if block.Type == "CERTIFICATE" || block.Type == "TRUSTED CERTIFICATE" {
				c, e := x509.ParseCertificate(block.Bytes)
				if e != nil {
					problem = e
				} else {
					visit(c)
				}
			}
			pending = pending[stop:]
		}
		if err == io.EOF {
			if bytes.Contains(pending, []byte(begin)) {
				problem = fmt.Errorf("unterminated PEM")
			}
			return problem
		}
		if err != nil {
			return err
		}
	}
}

// JKS trusted entries only. Integrity digest is not authenticated; no passwords
// or private keys are needed. Reject unsupported formats rather than claiming clean.
func parseJKS(data []byte) ([]*x509.Certificate, error) {
	r := bytes.NewReader(data)
	read32 := func() (uint32, error) { var v uint32; e := binary.Read(r, binary.BigEndian, &v); return v, e }
	magic, e := read32()
	if e != nil || magic != 0xfeedfeed {
		return nil, fmt.Errorf("invalid JKS magic")
	}
	version, e := read32()
	if e != nil || (version != 1 && version != 2) {
		return nil, fmt.Errorf("unsupported JKS version")
	}
	count, e := read32()
	if e != nil {
		return nil, e
	}
	skipUTF := func() error {
		var n uint16
		if e := binary.Read(r, binary.BigEndian, &n); e != nil {
			return e
		}
		if int(n) > r.Len() {
			return io.ErrUnexpectedEOF
		}
		_, e := r.Seek(int64(n), io.SeekCurrent)
		return e
	}
	var certs []*x509.Certificate
	for i := uint32(0); i < count; i++ {
		tag, e := read32()
		if e != nil || tag != 2 {
			return nil, fmt.Errorf("unsupported or truncated JKS entry")
		}
		if e = skipUTF(); e != nil {
			return nil, e
		}
		var timestamp uint64
		if e = binary.Read(r, binary.BigEndian, &timestamp); e != nil {
			return nil, e
		}
		if version == 2 {
			if e = skipUTF(); e != nil {
				return nil, e
			}
		}
		n, e := read32()
		if e != nil || uint64(n) > uint64(r.Len()) {
			return nil, io.ErrUnexpectedEOF
		}
		der := make([]byte, int(n))
		if _, e = io.ReadFull(r, der); e != nil {
			return nil, e
		}
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, e
		}
		certs = append(certs, c)
	}
	if r.Len() != 20 {
		return nil, fmt.Errorf("invalid JKS digest length")
	}
	return certs, nil
}
