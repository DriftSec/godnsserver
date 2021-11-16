package main

import "godnsserver/godns"

func main() {
	c := godns.New()
	c.Addr = "127.0.0.1"
	c.Port = "5354"
	c.Domain = "test.com"
	c.DefaultAnswer = "123.1.2.44"
	c.Records.A["test"] = "123.1.2.3"
	c.Records.A["test.google.com"] = "8.8.8.8"
	c.Records.TXT["cradle"] = "IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)IEX(blah.lbhadfasdf).DoPowershellstuff($pwn)"
	c.JSONDoLog = true
	c.JSONLogFile = "./dnslog.json"
	c.Blacklist = append(c.Blacklist, "127.0.0.*")
	c.Run()
}
