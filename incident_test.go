package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// Public incident chain captured by the incident reporter on 2026-10-20.
// Source: https://emudhra.we-have-a-problem.com/chains.zip
// Verify signatures without depending on the short-lived leaf's expiry date.
func TestIncidentSignatures(t *testing.T) {
	data, e := os.ReadFile("testdata/dv-g3b-chain.pem")
	if e != nil {
		t.Fatal(e)
	}
	var chain []*x509.Certificate
	for len(data) > 0 {
		b, rest := pem.Decode(data)
		if b == nil {
			break
		}
		data = rest
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			t.Fatal(e)
		}
		chain = append(chain, c)
	}
	if len(chain) != 3 {
		t.Fatal("expected three certificates")
	}
	for i := 0; i < 2; i++ {
		if e := chain[i].CheckSignatureFrom(chain[i+1]); e != nil {
			t.Fatal(e)
		}
	}
	if classify(chain[0]) != "" || classify(chain[1]) == "" || classify(chain[2]) == "" {
		t.Fatal("incorrect incident key identities")
	}
}
