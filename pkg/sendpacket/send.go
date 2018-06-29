package sendpacket

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = true
	err          error
	timeout      time.Duration = 500 * time.Millisecond
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

func SendIPIPPacket(device string, dstIP string, dstPort uint16, dstMAC string) error {
	bmac, err := net.ParseMAC(dstMAC)
	if err != nil {
		return err
	}

	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()

	buffer = gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	srcMAC := getHwAddr(device)
	srcIPv4 := getIfaceIpv4(device)[0]

	fmt.Printf("send packet from: %s:%s ==> %s:%s\n",
		srcMAC.String(), srcIPv4.String(), dstMAC, dstIP)
	fmt.Println("send ipip packet")

	etherLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       bmac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		TTL:      uint8(10),
		SrcIP:    srcIPv4.To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
		Version:  4,
		Protocol: layers.IPProtocolIPv4,
	}
	ipLayerInner := &layers.IPv4{
		TTL:      uint8(10),
		SrcIP:    srcIPv4.To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
		Version:  4,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(60000),
		DstPort: layers.TCPPort(dstPort),
		Seq:     7801,
		Window:  14600,
		SYN:     true,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, opt, etherLayer, ipLayer, ipLayerInner, tcpLayer)
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return err
	}
	data, _, err := handle.ReadPacketData()
	if err != nil {
		return err
	}
	printRawHex(data)
	return nil

}

func SendTCPPacket(device string, dstIP string, dstPort uint16, dstMAC string) error {
	bmac, err := net.ParseMAC(dstMAC)
	if err != nil {
		return err
	}

	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()

	buffer = gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	srcMAC := getHwAddr(device)
	srcIPv4 := getIfaceIpv4(device)[0]

	fmt.Printf("send packet from: %s:%s ==> %s:%s\n",
		srcMAC.String(), srcIPv4.String(), dstMAC, dstIP)
	fmt.Println("send tcp packet")

	etherLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       bmac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		TTL:      uint8(10),
		SrcIP:    srcIPv4.To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
		Version:  4,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(60000),
		DstPort: layers.TCPPort(dstPort),
		Seq:     7801,
		Window:  14600,
		SYN:     true,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, opt, etherLayer, ipLayer, tcpLayer)
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return err
	}
	data, _, err := handle.ReadPacketData()
	if err != nil {
		return err
	}
	printRawHex(data)
	return nil

}

func getHwAddr(iface string) net.HardwareAddr {
	ret := net.HardwareAddr{}
	faces, err := net.Interfaces()
	if err != nil {
		return ret
	}

	for _, i := range faces {
		if i.Name == iface {
			return i.HardwareAddr
		}
	}
	return ret
}

func getIfaceIpv4(iface string) []net.IP {
	var ret []net.IP
	faces, err := net.Interfaces()
	if err != nil {
		return ret
	}

	ret = make([]net.IP, 15)
	validCount := 0
	for _, i := range faces {
		if i.Name != iface {
			continue
		}
		ipAddr, err := i.Addrs()
		if err != nil {
			return ret
		}

		for _, addr := range ipAddr {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					if validCount < len(ret) {
						ret[validCount] = ipnet.IP
					} else {
						ret = append(ret, ipnet.IP)
					}
					validCount++
				}
			}
		}
	}
	return ret[:validCount]
}

func printRawHex(data []byte) {
	for i, octet := range data {
		fmt.Printf("%02x ", octet)
		if i%16 == 15 {
			fmt.Println()
		}
	}
	fmt.Println()
}
