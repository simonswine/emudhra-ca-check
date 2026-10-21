package main

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	for _, tc := range []struct{ cn, status string }{
		{"AAA Certificate Services", "no-matching-pem-certificates"},
		{"emSign Root CA - G1", "no-matching-pem-certificates"},
		{"EM DV TLS CA - G3B", "no-matching-pem-certificates"},
		{"Unrelated Root", "no-matching-pem-certificates"},
	} {
		t.Run(tc.cn, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: tc.cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
			if tc.cn == "emSign Root CA - G1" {
				c.Subject.Organization = []string{"eMudhra Inc"}
			}
			der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			out, err := scan(bytes.NewReader(archive(t, data)))
			if err != nil {
				t.Fatal(err)
			}
			if out.Status != tc.status || out.Certificates != 1 {
				t.Fatalf("unexpected report: %+v", out)
			}
		})
	}
}
func archive(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: "etc/ssl/certs/ca-certificates.crt", Mode: 0644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestInconclusive(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----")} {
		out, err := scan(bytes.NewReader(archive(t, data)))
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != "inconclusive" {
			t.Fatalf("unexpected report: %+v", out)
		}
	}
}
