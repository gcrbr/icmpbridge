package main

import (
	"flag"
	"fmt"
	"log"
)

func initLogging() {
	log.SetPrefix("[\033[0;34mINFO\033[0m] ")
	log.SetFlags(0)
}

func main() {
	fmt.Printf("\033[0;35micmpbridge\033[0m :: created by @gcrbr\n\n")
	
	_interface := flag.String("i", "en0", "Interface to listen to for ICMP packets")
	rulesFile := flag.String("r", "rules.yml", "Rules file")
	password := flag.String("p", "bridge123", "Server password")

	flag.Parse()

	serverPassword = *password

	initLogging()
	parseRules(*rulesFile)
	go cleanClientList()
	initICMPService(_interface)
}