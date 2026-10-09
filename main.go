// npm-dns is a tiny DNS server that answers for the server_names found in a
// Nginx Proxy Manager data directory, using CNAME_* / A_* rules from the
// environment, and forwards everything else to a public resolver.
//
// Configuration (environment variables):
//
//	CNAME_<domain>=<target>  CNAME for <domain> and every name under it
//	A_<host>=<ipv4>[,<ipv4>] A record(s) for exactly <host>
//	FALLBACK=1.1.1.1[:53]    upstream resolver(s), comma separated
//	LISTEN=:53               address to listen on (UDP and TCP)
//	NPM_DATA=./data/nginx    NPM nginx directory containing proxy_host/
//	TTL=60                   TTL for locally generated records
//	LOG_QUERIES=1            log every query and how it was answered
//
// In variable names, "_" stands for "." and "__" for "-":
//
//	CNAME_jcgurango_com=rts.jcgurango.com
//	CNAME_chat_jcgurango_com=serverb.jcgurango.com
//	A_rts_jcgurango_com=192.168.0.212
//	A_rest__backend_jcgurango_com=192.168.0.5   # rest-backend.jcgurango.com
package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func main() {
	r, err := rulesFromEnv(os.Environ())
	if err != nil {
		log.Fatal(err)
	}

	dataDir := envOr("NPM_DATA", "./data/nginx")
	if _, err := os.Stat(dataDir); err != nil {
		log.Fatalf("NPM_DATA: %v", err)
	}

	var fallbacks []string
	for _, f := range strings.Split(os.Getenv("FALLBACK"), ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(f); err != nil {
			f = net.JoinHostPort(f, "53")
		}
		fallbacks = append(fallbacks, f)
	}

	ttl, err := strconv.ParseUint(envOr("TTL", "60"), 10, 32)
	if err != nil {
		log.Fatalf("TTL: %v", err)
	}
	logQueries := os.Getenv("LOG_QUERIES") != "" && os.Getenv("LOG_QUERIES") != "0"
	listen := envOr("LISTEN", ":53")

	srv := newServer(r, dataDir, fallbacks, uint32(ttl), logQueries)

	hosts, err := loadNPMHosts(dataDir)
	if err != nil {
		log.Fatalf("reading NPM config: %v", err)
	}
	log.Printf("npm-dns listening on %s (udp+tcp)", listen)
	log.Printf("NPM data: %s (%d server_names found, re-read on every query)", dataDir, len(hosts))
	if len(fallbacks) > 0 {
		log.Printf("fallback: %s", strings.Join(fallbacks, ", "))
	} else {
		log.Printf("no FALLBACK set: unmatched queries will be REFUSED")
	}
	if s := r.String(); s != "" {
		log.Printf("rules:\n%s", s)
	} else {
		log.Printf("no CNAME_*/A_* rules configured")
	}

	errc := make(chan error, 2)
	for _, network := range []string{"udp", "tcp"} {
		go func(net string) {
			errc <- (&dns.Server{Addr: listen, Net: net, Handler: srv}).ListenAndServe()
		}(network)
	}
	log.Fatal(<-errc)
}
