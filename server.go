package main

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const maxChainDepth = 8

type server struct {
	rules      *rules
	dataDir    string
	fallbacks  []string // upstream resolvers as host:port, tried in order
	ttl        uint32
	logQueries bool
	udp, tcp   *dns.Client
}

func newServer(r *rules, dataDir string, fallbacks []string, ttl uint32, logQueries bool) *server {
	return &server{
		rules:      r,
		dataDir:    dataDir,
		fallbacks:  fallbacks,
		ttl:        ttl,
		logQueries: logQueries,
		udp:        &dns.Client{Net: "udp", Timeout: 3 * time.Second},
		tcp:        &dns.Client{Net: "tcp", Timeout: 3 * time.Second},
	}
}

func (s *server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := s.handle(req, w.RemoteAddr().Network() == "tcp")
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("write response: %v", err)
	}
}

func (s *server) handle(req *dns.Msg, viaTCP bool) *dns.Msg {
	if len(req.Question) != 1 || req.Opcode != dns.OpcodeQuery {
		return errorReply(req, dns.RcodeFormatError)
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET {
		return s.forward(req, viaTCP)
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	hosts, err := loadNPMHosts(s.dataDir)
	if err != nil {
		log.Printf("reading NPM config: %v", err)
		return errorReply(req, dns.RcodeServerFailure)
	}

	rrs, handled := s.resolveLocal(name, q.Qtype, hosts, viaTCP, 0)
	if !handled {
		if s.logQueries {
			log.Printf("%s %s -> fallback", dns.TypeToString[q.Qtype], name)
		}
		return s.forward(req, viaTCP)
	}
	if s.logQueries {
		log.Printf("%s %s -> %s", dns.TypeToString[q.Qtype], name, describe(rrs))
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	resp.Answer = rrs
	return resp
}

// resolveLocal answers name/qtype from the configured rules. handled is
// false when no rule applies and the query should go to the fallback.
//
// Precedence:
//  1. An A_* rule matching the exact name.
//  2. If the name is served by an NPM proxy host, the most specific CNAME_*
//     rule for the name or one of its parent domains.
//  3. Otherwise: not handled.
func (s *server) resolveLocal(name string, qtype uint16, hosts []npmHost, viaTCP bool, depth int) (rrs []dns.RR, handled bool) {
	fqdn := dns.Fqdn(name)

	if ips, ok := s.rules.a[name]; ok {
		if qtype == dns.TypeA || qtype == dns.TypeANY {
			for _, ip := range ips {
				rrs = append(rrs, &dns.A{Hdr: s.header(fqdn, dns.TypeA), A: ip})
			}
		}
		return rrs, true // other types: NODATA
	}

	if !matchesNPM(hosts, name) {
		return nil, false
	}
	target, ok := s.rules.lookupCNAME(name)
	if !ok || target == name {
		return nil, false
	}
	rrs = append(rrs, &dns.CNAME{Hdr: s.header(fqdn, dns.TypeCNAME), Target: dns.Fqdn(target)})
	if qtype == dns.TypeCNAME || depth >= maxChainDepth {
		return rrs, true
	}

	// Chase the CNAME so clients get the final address in one round trip.
	sub, subHandled := s.resolveLocal(target, qtype, hosts, viaTCP, depth+1)
	if subHandled {
		return append(rrs, sub...), true
	}
	if len(s.fallbacks) > 0 {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(target), qtype)
		q.RecursionDesired = true
		if up, err := s.exchange(q, viaTCP); err == nil && up.Rcode == dns.RcodeSuccess {
			rrs = append(rrs, up.Answer...)
		}
	}
	return rrs, true
}

func (s *server) header(fqdn string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: fqdn, Rrtype: rrtype, Class: dns.ClassINET, Ttl: s.ttl}
}

// forward relays req to the fallback resolver and returns its reply.
func (s *server) forward(req *dns.Msg, viaTCP bool) *dns.Msg {
	if len(s.fallbacks) == 0 {
		return errorReply(req, dns.RcodeRefused)
	}
	resp, err := s.exchange(req, viaTCP)
	if err != nil {
		log.Printf("fallback query for %s failed: %v", req.Question[0].Name, err)
		return errorReply(req, dns.RcodeServerFailure)
	}
	resp.Id = req.Id
	return resp
}

func (s *server) exchange(req *dns.Msg, viaTCP bool) (*dns.Msg, error) {
	var lastErr error
	for _, up := range s.fallbacks {
		var resp *dns.Msg
		var err error
		if viaTCP {
			resp, _, err = s.tcp.Exchange(req, up)
		} else {
			resp, _, err = s.udp.Exchange(req, up)
			if err == nil && resp.Truncated {
				resp, _, err = s.tcp.Exchange(req, up)
			}
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no fallback resolvers")
	}
	return nil, lastErr
}

func errorReply(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	return m
}

func describe(rrs []dns.RR) string {
	if len(rrs) == 0 {
		return "NODATA"
	}
	parts := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.CNAME:
			parts = append(parts, "CNAME "+v.Target)
		case *dns.A:
			parts = append(parts, "A "+v.A.String())
		case *dns.AAAA:
			parts = append(parts, "AAAA "+v.AAAA.String())
		default:
			parts = append(parts, dns.TypeToString[rr.Header().Rrtype])
		}
	}
	return strings.Join(parts, ", ")
}
