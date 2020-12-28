package dnsserver

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

// This struct implements the ServeDNS method of the Handler interface
type staticHandler struct {
	IP     string
	Domain *string
	TXT    *string
}

// ServeDNS is a method that handles dns lookups
func (s *staticHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := dns.Msg{}
	m.SetReply(r)

	if r.Question[0].Qtype == dns.TypeA {
		m.Authoritative = true
		domain := m.Question[0].Name
		m.Answer = append(
			m.Answer,
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: net.ParseIP(s.IP),
			})
	}

	if r.Question[0].Qtype == dns.TypeTXT {
		m.Authoritative = true
		m.Answer = append(
			m.Answer,
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   *(s.Domain),
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Txt: []string{*(s.TXT)},
			})
	}

	w.WriteMsg(&m)
}

// StartDNS creates a DNS service on port 10053 that will respond to all
// A record lookups with the given ip
func StartDNS(ip string, domain, txt *string) {
	srv := &dns.Server{Addr: ":10053", Net: "udp"}
	srv.Handler = &staticHandler{
		IP:     ip,
		Domain: domain,
		TXT:    txt,
	}
	log.Printf("Starting DNS server on :10053\n")
	err := srv.ListenAndServe()
	if err != nil {
		log.Fatalf("Error creating DNS server %s\n", err.Error())
	}
}
