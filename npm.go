package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// npmHost is one server_name pattern from an NPM proxy host config.
// If wildcard is true, name is the suffix (e.g. "test.aruga.in") and any
// name underneath it matches; otherwise name must match exactly.
type npmHost struct {
	name     string
	wildcard bool
}

// loadNPMHosts reads every *.conf under <dataDir>/proxy_host and returns the
// server_name entries found. Regex server_names (~...) are ignored.
// It is called on every query so that edits to the data dir are seen
// immediately.
func loadNPMHosts(dataDir string) ([]npmHost, error) {
	files, err := filepath.Glob(filepath.Join(dataDir, "proxy_host", "*.conf"))
	if err != nil {
		return nil, err
	}
	var hosts []npmHost
	for _, f := range files {
		h, err := parseServerNames(f)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h...)
	}
	return hosts, nil
}

func parseServerNames(path string) ([]npmHost, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	var hosts []npmHost
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		if len(fields) < 2 || fields[0] != "server_name" {
			continue
		}
		for _, n := range fields[1:] {
			n = strings.ToLower(strings.TrimSuffix(n, "."))
			switch {
			case strings.HasPrefix(n, "~"), n == "", n == "_":
				continue
			case strings.HasPrefix(n, "*."):
				hosts = append(hosts, npmHost{name: n[2:], wildcard: true})
			case strings.HasPrefix(n, "."):
				// nginx: ".example.com" == "example.com *.example.com"
				hosts = append(hosts, npmHost{name: n[1:]}, npmHost{name: n[1:], wildcard: true})
			default:
				hosts = append(hosts, npmHost{name: n})
			}
		}
	}
	return hosts, sc.Err()
}

// matchesNPM reports whether name (lowercase, no trailing dot) is served by
// one of the NPM proxy hosts.
func matchesNPM(hosts []npmHost, name string) bool {
	for _, h := range hosts {
		if h.name == name {
			return true
		}
		if h.wildcard && strings.HasSuffix(name, "."+h.name) {
			return true
		}
	}
	return false
}
