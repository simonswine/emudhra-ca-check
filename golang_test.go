package main

import (
	"bytes"
	"os"
	"testing"
)

func TestGoVersionStatus(t *testing.T) {
	for _, tc := range []struct{ v, want string }{
		{"go1.25.20", "below-minimum"}, {"go1.26.9", "below-minimum"},
		{"go1.26.10", "meets-minimum"}, {"go1.26.11", "meets-minimum"},
		{"go1.27.0", "below-minimum"}, {"go1.27.2", "below-minimum"},
		{"go1.27.3", "meets-minimum"}, {"go1.27.10", "meets-minimum"},
		{"go1.28.0", "meets-minimum"}, {"go1.28rc1", "unknown"},
		{"devel go1.28-abcdef", "unknown"}, {"garbage", "unknown"},
	} {
		t.Run(tc.v, func(t *testing.T) {
			if got := goVersionStatus(tc.v); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestScanGoBinary(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := scan(bytes.NewReader(archive(t, data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.GoBinaries) != 1 || out.GoBinaries[0].Version == "" {
		t.Fatalf("missing Go build info: %+v", out)
	}
	if out.hasOldGo() && out.Status != "potential-exposure" {
		t.Fatalf("unexpected status: %s", out.Status)
	}
}
