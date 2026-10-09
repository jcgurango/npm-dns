package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestEnvToName(t *testing.T) {
	cases := map[string]string{
		"chat_jcgurango_com":          "chat.jcgurango.com",
		"rest-backend_jcgurango_com":  "rest-backend.jcgurango.com",
		"rest__backend_jcgurango_com": "rest-backend.jcgurango.com",
		"JCGURANGO_COM":               "jcgurango.com",
	}
	for in, want := range cases {
		if got := envToName(in); got != want {
			t.Errorf("envToName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseServerNames(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "proxy_host"), 0o755)
	os.WriteFile(filepath.Join(dir, "proxy_host", "1.conf"), []byte(`
server {
  server_name *.test.aruga.in test.aruga.in; # comment
  server_name  Foo.Example.COM;
  server_name .dot.example.com;
  server_name ~^regex\.example\.com$;
}`), 0o644)
	hosts, err := loadNPMHosts(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []npmHost{
		{"test.aruga.in", true}, {"test.aruga.in", false},
		{"foo.example.com", false},
		{"dot.example.com", false}, {"dot.example.com", true},
	}
	if len(hosts) != len(want) {
		t.Fatalf("got %v, want %v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Errorf("hosts[%d] = %v, want %v", i, hosts[i], want[i])
		}
	}
	for name, want := range map[string]bool{
		"test.aruga.in": true, "a.test.aruga.in": true, "a.b.test.aruga.in": true,
		"xtest.aruga.in": false, "foo.example.com": true, "bar.foo.example.com": false,
		"dot.example.com": true, "x.dot.example.com": true,
	} {
		if got := matchesNPM(hosts, name); got != want {
			t.Errorf("matchesNPM(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestLookupCNAME(t *testing.T) {
	r, err := rulesFromEnv([]string{
		"CNAME_jcgurango_com=rts.jcgurango.com",
		"CNAME_chat_jcgurango_com=serverb.jcgurango.com",
		"A_rts_jcgurango_com=192.168.0.212",
		"PATH=/usr/bin",
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"jcgurango.com":          "rts.jcgurango.com",
		"git.jcgurango.com":      "rts.jcgurango.com",
		"chat.jcgurango.com":     "serverb.jcgurango.com",
		"sub.chat.jcgurango.com": "serverb.jcgurango.com",
		"com":                    "",
		"example.com":            "",
	} {
		got, ok := r.lookupCNAME(name)
		if got != want || ok != (want != "") {
			t.Errorf("lookupCNAME(%q) = %q,%v; want %q", name, got, ok, want)
		}
	}
	if len(r.a["rts.jcgurango.com"]) != 1 || !r.a["rts.jcgurango.com"][0].Equal(net.ParseIP("192.168.0.212")) {
		t.Errorf("A rule not parsed: %v", r.a)
	}
	if _, err := rulesFromEnv([]string{"A_x_com=nope"}); err == nil {
		t.Error("expected error for bad IP")
	}
}

// stubUpstream is a fake fallback resolver that answers every A query with
// 9.9.9.9 and records what it was asked.
func stubUpstream(t *testing.T) (addr string, asked *[]string) {
	t.Helper()
	asked = &[]string{}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		*asked = append(*asked, req.Question[0].Name)
		m := new(dns.Msg)
		m.SetReply(req)
		if req.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
				A:   net.ParseIP("9.9.9.9").To4(),
			}}
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String(), asked
}

func TestResolution(t *testing.T) {
	upstream, asked := stubUpstream(t)
	r, err := rulesFromEnv([]string{
		"CNAME_jcgurango_com=rts.jcgurango.com",
		"CNAME_chat_jcgurango_com=serverb.jcgurango.com",
		"CNAME_aruga_in=rts.jcgurango.com",
		"A_rts_jcgurango_com=192.168.0.212",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(r, "data/nginx", []string{upstream}, 60, false)

	type want struct {
		rcode int
		rrs   []string // "TYPE value"
	}
	cases := []struct {
		name  string
		qtype uint16
		want  want
	}{
		// NPM server_name under a CNAME rule, target has a local A record.
		{"git.jcgurango.com", dns.TypeA, want{dns.RcodeSuccess, []string{"CNAME rts.jcgurango.com.", "A 192.168.0.212"}}},
		// Apex is itself an NPM server_name.
		{"jcgurango.com", dns.TypeA, want{dns.RcodeSuccess, []string{"CNAME rts.jcgurango.com.", "A 192.168.0.212"}}},
		// Case-insensitive.
		{"GIT.JCGURANGO.COM", dns.TypeA, want{dns.RcodeSuccess, []string{"CNAME rts.jcgurango.com.", "A 192.168.0.212"}}},
		// More specific rule wins; target is not local so it's chased upstream.
		{"chat.jcgurango.com", dns.TypeA, want{dns.RcodeSuccess, []string{"CNAME serverb.jcgurango.com.", "A 9.9.9.9"}}},
		// AAAA query for a CNAME'd name: CNAME only (upstream stub has no AAAA).
		{"chat.jcgurango.com", dns.TypeAAAA, want{dns.RcodeSuccess, []string{"CNAME serverb.jcgurango.com."}}},
		// CNAME query: no chasing.
		{"git.jcgurango.com", dns.TypeCNAME, want{dns.RcodeSuccess, []string{"CNAME rts.jcgurango.com."}}},
		// A rule: exact only, no CNAME.
		{"rts.jcgurango.com", dns.TypeA, want{dns.RcodeSuccess, []string{"A 192.168.0.212"}}},
		// A rule does not cover subdomains; not an NPM name either -> upstream.
		{"x.rts.jcgurango.com", dns.TypeA, want{dns.RcodeSuccess, []string{"A 9.9.9.9"}}},
		// AAAA for an A-only name: NODATA.
		{"rts.jcgurango.com", dns.TypeAAAA, want{dns.RcodeSuccess, nil}},
		// Not an NPM server_name -> upstream even though a CNAME rule covers the zone.
		{"nothere.jcgurango.com", dns.TypeA, want{dns.RcodeSuccess, []string{"A 9.9.9.9"}}},
		// NPM wildcard server_name.
		{"foo.test.aruga.in", dns.TypeA, want{dns.RcodeSuccess, []string{"CNAME rts.jcgurango.com.", "A 192.168.0.212"}}},
		{"test.aruga.in", dns.TypeA, want{dns.RcodeSuccess, []string{"CNAME rts.jcgurango.com.", "A 192.168.0.212"}}},
		// NPM server_name with no CNAME rule for its zone -> upstream.
		{"fayewrites.net", dns.TypeA, want{dns.RcodeSuccess, []string{"A 9.9.9.9"}}},
		// Totally unrelated name -> upstream.
		{"example.org", dns.TypeA, want{dns.RcodeSuccess, []string{"A 9.9.9.9"}}},
	}
	for _, c := range cases {
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(c.name), c.qtype)
		resp := s.handle(req, false)
		if resp.Rcode != c.want.rcode {
			t.Errorf("%s %s: rcode %s, want %s", dns.TypeToString[c.qtype], c.name, dns.RcodeToString[resp.Rcode], dns.RcodeToString[c.want.rcode])
		}
		var got []string
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.CNAME:
				got = append(got, "CNAME "+v.Target)
			case *dns.A:
				got = append(got, "A "+v.A.String())
			default:
				got = append(got, rr.String())
			}
		}
		if len(got) != len(c.want.rrs) {
			t.Errorf("%s %s: got %v, want %v", dns.TypeToString[c.qtype], c.name, got, c.want.rrs)
			continue
		}
		for i := range got {
			if got[i] != c.want.rrs[i] {
				t.Errorf("%s %s: answer[%d] = %q, want %q", dns.TypeToString[c.qtype], c.name, i, got[i], c.want.rrs[i])
			}
		}
	}
	for _, q := range *asked {
		if q == "git.jcgurango.com." || q == "rts.jcgurango.com." || q == "jcgurango.com." {
			t.Errorf("locally answered name %s was sent upstream", q)
		}
	}
}

func TestNoFallback(t *testing.T) {
	r, _ := rulesFromEnv(nil)
	s := newServer(r, "data/nginx", nil, 60, false)
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	if resp := s.handle(req, false); resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

// Edits to the data dir must be visible without a restart.
func TestFreshLookup(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "proxy_host"), 0o755)
	r, _ := rulesFromEnv([]string{"CNAME_example_com=target.example.net", "A_target_example_net=10.0.0.1"})
	s := newServer(r, dir, nil, 60, false)
	req := new(dns.Msg)
	req.SetQuestion("new.example.com.", dns.TypeA)
	if resp := s.handle(req, false); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("before adding host: rcode %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	os.WriteFile(filepath.Join(dir, "proxy_host", "9.conf"), []byte("server_name new.example.com;\n"), 0o644)
	if resp := s.handle(req, false); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 2 {
		t.Fatalf("after adding host: rcode %s, answers %v", dns.RcodeToString[resp.Rcode], resp.Answer)
	}
}
