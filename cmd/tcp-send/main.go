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
	dstPort    int
	sendDevice string
)

func main() {
	flag.StringVar(&dstIP, "dst-ip", "", "destination IP")
	flag.StringVar(&dstMac, "dst-mac", "", "destination MAC")
	flag.StringVar(&sendDevice, "dev", "", "send device")
	flag.IntVar(&dstPort, "dst-port", 0, "destination port")
	flag.Parse()

	err := sendpacket.SendTCPPacket(sendDevice, dstIP, uint16(dstPort), dstMac)
	if err != nil {
		log.Printf("error in send TCP packet: %v", err)
		os.Exit(1)
	}
	os.Exit(0)
}
