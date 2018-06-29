package main

import (
	"flag"
	"log"
	"os"

	"github.com/randmonkey/calico-precheck/pkg/sendpacket"
)

var (
	dstIP      string
	dstMac     string
	sendDevice string
)

func main() {
	flag.StringVar(&dstIP, "dst-ip", "", "destination IP")
	flag.StringVar(&dstMac, "dst-mac", "", "destination MAC")
	flag.StringVar(&sendDevice, "dev", "", "send device")
	flag.Parse()

	err := sendpacket.SendIPIPPacket(sendDevice, dstIP, uint16(61234), dstMac)
	if err != nil {
		log.Printf("error in send ipip packet: %v", err)
		os.Exit(1)
	}
	os.Exit(0)

}
