package godns

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/DriftSec/getasn"
	"github.com/miekg/dns"
)

type DnsLog struct {
	Timestamp  string `json:"timestamp"`
	RemoteAddr string `json:"remote_addr"`
	QType      string `json:"q_type"`
	QName      string `json:"q_name"`
	Answer     string `json:"q_answer"`
	Exfil      string `json:"exfil"`
	IPInfo     *getasn.IPInfo
}

var Qtypes = map[int]string{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	15: "MX",
	16: "TXT",
	28: "AAAA",
}

var JSON []DnsLog

func (dc *DNSConfig) LogQuery(question dns.Question, m *dns.Msg, w dns.ResponseWriter, r *dns.Msg, answer string, ipinf getasn.IPInfo) {
	if !dc.JSONDoLog {
		return
	}
	dl := &DnsLog{}
	dl.Timestamp = time.Now().Format("2006/02/01 15:04:05")
	dl.RemoteAddr = w.RemoteAddr().String()
	dl.QType = Qtypes[int(question.Qtype)]
	dl.QName = question.Name
	dl.Answer = answer
	dl.IPInfo = &ipinf
	if dl.QType == "TXT" {
		dl.Answer = dc.Records.TXT[answer]
	}
	dl.Exfil = strings.Join(dc.parseForExfil(question.Name), ",")

	dc.appendJSONFile(*dl)
}

func (dc *DNSConfig) appendJSONFile(rl DnsLog) {
	// assume err is because new file/no data
	tmpdata, _ := os.ReadFile(dc.JSONLogFile)
	json.Unmarshal(tmpdata, &JSON)
	JSON = append(JSON, rl)

	data, err := json.MarshalIndent(JSON, "", "     ")
	if err != nil {
		fmt.Println("[ERROR] JSON Logger:", err)
		return
	}
	err = os.WriteFile(dc.JSONLogFile, data, 0755)
	if err != nil {
		log.Fatal("Failed to log JSON to file")
	}
}
