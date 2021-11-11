package main

import "godnsserver/godns"

func main() {
	godns.DnsCfg.Domain = "test.com"
	godns.DnsCfg.DefaultAnswer = "123.1.2.44"
	godns.DnsCfg.CustomAnswers = make(map[string]string)
	godns.DnsCfg.CustomAnswers["test"] = "123.1.2.3"
	godns.DnsCfg.CustomAnswers["test.google.com"] = "8.8.8.8"

	godns.DnsCfg.TXTRecords = make(map[string]string)
	godns.DnsCfg.TXTRecords["cradle"] = "IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)"
	godns.DnsCfg.JSONDoLog = true
	godns.DnsCfg.JSONLogFile = "./dnslog.json"
	godns.Run()
}
