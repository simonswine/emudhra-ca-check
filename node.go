package main

import (
	"encoding/json"
	"strings"
)

func nodePolicy(raw string) string {
	var c struct{ Entrypoint, Cmd, Env []string }
	if json.Unmarshal([]byte(raw), &c) != nil {
		return "invalid image configuration"
	}
	// Only recognize a direct node invocation; wrappers and shell commands are unknown.
	args := append(append([]string{}, c.Entrypoint...), c.Cmd...)
	if len(args) == 0 || !(args[0] == "node" || strings.HasSuffix(args[0], "/node")) {
		return "unknown entrypoint"
	}
	system := false
	for _, env := range c.Env {
		if strings.HasPrefix(env, "NODE_OPTIONS=") {
			for _, v := range strings.Fields(strings.TrimPrefix(env, "NODE_OPTIONS=")) {
				if v == "--use-openssl-ca" {
					system = true
				}
				if v == "--use-bundled-ca" {
					return "bundled CA requested"
				}
			}
		}
	}
	for _, v := range args[1:] {
		if v == "--" || !strings.HasPrefix(v, "-") {
			break
		}
		if v == "--use-bundled-ca" {
			return "bundled CA requested"
		}
		if v == "--use-openssl-ca" {
			system = true
		}
	}
	if system {
		return "system CA requested; runtime overrides remain possible"
	}
	return "embedded CA store may be used"
}
