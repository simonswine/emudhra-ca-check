package main

import (
	"os"
	"strings"
	"testing"
)

func TestLevelLabelNonTerminal(t *testing.T) {
	if value, ok := os.LookupEnv("NO_COLOR"); ok {
		if err := os.Unsetenv("NO_COLOR"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Setenv("NO_COLOR", value) })
	}
	t.Setenv("TERM", "xterm-256color")

	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	for _, stream := range []*os.File{file, null} {
		if got := levelLabel("CRITICAL", stream); got != "[CRITICAL]" {
			t.Errorf("%s: got %q, want plain label", stream.Name(), got)
		}
	}
}

func TestReportLevel(t *testing.T) {
	for status, want := range map[string]string{
		"potential-exposure":           "CRITICAL",
		"inconclusive":                 "UNKNOWN",
		"no-matching-pem-certificates": "INFO",
	} {
		if got := reportLevel(status); got != want {
			t.Errorf("%s: got %s, want %s", status, got, want)
		}
	}
}

func TestScanWarning(t *testing.T) {
	message := "bin/app: unterminated PEM"
	got := scanWarning(message)
	if !strings.HasPrefix(got, message) || !strings.Contains(got, "not evidence of an affected certificate") || !strings.Contains(got, "incomplete") {
		t.Fatalf("missing PEM warning context: %s", got)
	}
	if got := scanWarning("store.jks: invalid JKS"); got != "store.jks: invalid JKS" {
		t.Fatal(got)
	}
}
