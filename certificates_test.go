package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCryptographicIdentity(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Renamed root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	root, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	id := hex.EncodeToString(sum[:])
	blockedKeys[id] = "test key"
	defer delete(blockedKeys, id)
	if e = root.CheckSignatureFrom(root); e != nil {
		t.Fatal(e)
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"test.invalid"}, NotBefore: template.NotBefore, NotAfter: template.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(leafDER)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "test.invalid"}); e != nil {
		t.Fatal(e)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: "test.invalid"}); e == nil {
		t.Fatal("chain accepted without root")
	}
	template.SerialNumber = big.NewInt(3)
	template.Subject.CommonName = "Different name, same key"
	reissued, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	for _, d := range [][]byte{der, reissued} {
		out, e := scan(bytes.NewReader(archive(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))))
		if e != nil || len(out.Findings) != 1 {
			t.Fatalf("%+v %v", out, e)
		}
	}
	var jks bytes.Buffer
	for _, v := range []uint32{0xfeedfeed, 2, 1, 2} {
		binary.Write(&jks, binary.BigEndian, v)
	}
	binary.Write(&jks, binary.BigEndian, uint16(0))
	binary.Write(&jks, binary.BigEndian, uint64(0))
	binary.Write(&jks, binary.BigEndian, uint16(5))
	jks.WriteString("X.509")
	binary.Write(&jks, binary.BigEndian, uint32(len(der)))
	jks.Write(der)
	jks.Write(make([]byte, 20))
	out, e := scan(bytes.NewReader(archive(t, jks.Bytes())))
	if e != nil || len(out.Findings) != 1 {
		t.Fatalf("JKS: %+v %v", out, e)
	}
	for i := 0; i < jks.Len(); i++ {
		if _, e := parseJKS(jks.Bytes()[:i]); e == nil {
			t.Fatalf("accepted truncated JKS at %d", i)
		}
	}
	data := append(bytes.Repeat([]byte{0}, maxFile+1), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	out, e = scan(bytes.NewReader(archive(t, data)))
	if e != nil || len(out.Findings) != 1 || len(out.Skipped) != 0 {
		t.Fatalf("large file: %+v %v", out, e)
	}
}

func TestOversizedPEMEndMarker(t *testing.T) {
	for _, suffix := range []string{"", "-----"} {
		data := append([]byte("-----BEGIN CERTIFICATE-----\n-----END "), bytes.Repeat([]byte{'X'}, maxFile+1)...)
		data = append(data, suffix...)
		if err := scanPEM(bytes.NewReader(data), func(*x509.Certificate) {
			t.Fatal("unexpected certificate")
		}); err == nil {
			t.Fatal("accepted oversized PEM end marker")
		}
	}
}

func TestNodePolicy(t *testing.T) {
	for _, tc := range []struct {
		config string
		system bool
	}{
		{`{"Entrypoint":["/nodejs/bin/node","--use-openssl-ca"]}`, true},
		{`{"Entrypoint":["node"],"Env":["NODE_OPTIONS=--use-openssl-ca"]}`, true},
		{`{"Entrypoint":["node"],"Cmd":["app.js","--use-openssl-ca"]}`, false},
		{`{"Entrypoint":["node","--use-bundled-ca"]}`, false},
		{`{"Entrypoint":["sh","-c","node --use-openssl-ca"]}`, false},
	} {
		got := nodePolicy(tc.config) == "system CA requested; runtime overrides remain possible"
		if got != tc.system {
			t.Fatal(tc.config)
		}
	}
}
