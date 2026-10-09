package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// rules holds the static records configured through environment variables.
type rules struct {
	// cname maps a domain to its CNAME target. The rule applies to the
	// domain itself and everything under it; the longest matching domain wins.
	cname map[string]string
	// a maps a hostname to its A record(s). Exact match only.
	a map[string][]net.IP
}

// envToName converts an environment-variable suffix into a hostname:
// "chat_jcgurango_com" -> "chat.jcgurango.com". Hyphens are kept as-is, and
// a double underscore may be used in place of a hyphen for shells that can't
// export variables containing "-".
func envToName(s string) string {
	s = strings.ReplaceAll(s, "__", "-")
	s = strings.ReplaceAll(s, "_", ".")
	return strings.ToLower(strings.Trim(s, "."))
}

// rulesFromEnv parses CNAME_* and A_* variables from the given environment
// (os.Environ() style "KEY=VALUE" strings).
func rulesFromEnv(environ []string) (*rules, error) {
	r := &rules{cname: map[string]string{}, a: map[string][]net.IP{}}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case strings.HasPrefix(k, "CNAME_"):
			name := envToName(strings.TrimPrefix(k, "CNAME_"))
			target := strings.ToLower(strings.TrimSuffix(v, "."))
			if name == "" || target == "" {
				return nil, fmt.Errorf("invalid CNAME rule %q", kv)
			}
			r.cname[name] = target
		case strings.HasPrefix(k, "A_"):
			name := envToName(strings.TrimPrefix(k, "A_"))
			if name == "" {
				return nil, fmt.Errorf("invalid A rule %q", kv)
			}
			for _, s := range strings.FieldsFunc(v, func(c rune) bool { return c == ',' || c == ' ' }) {
				ip := net.ParseIP(s)
				if ip == nil || ip.To4() == nil {
					return nil, fmt.Errorf("invalid IPv4 address %q in %s", s, k)
				}
				r.a[name] = append(r.a[name], ip.To4())
			}
			if len(r.a[name]) == 0 {
				return nil, fmt.Errorf("no addresses given for %s", k)
			}
		}
	}
	return r, nil
}

// lookupCNAME finds the most specific CNAME rule covering name: an exact
// match, else the longest parent domain with a rule.
func (r *rules) lookupCNAME(name string) (target string, ok bool) {
	for n := name; n != ""; {
		if t, found := r.cname[n]; found {
			return t, true
		}
		_, rest, hasDot := strings.Cut(n, ".")
		if !hasDot {
			break
		}
		n = rest
	}
	return "", false
}

func (r *rules) String() string {
	var lines []string
	for n, t := range r.cname {
		lines = append(lines, fmt.Sprintf("CNAME %s (and subdomains) -> %s", n, t))
	}
	for n, ips := range r.a {
		var s []string
		for _, ip := range ips {
			s = append(s, ip.String())
		}
		lines = append(lines, fmt.Sprintf("A     %s -> %s", n, strings.Join(s, ",")))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
