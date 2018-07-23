package capturepacket

import (
	"fmt"
	"math"
	"net"
	"os/exec"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	etherHeaderLength = 14
	ipv4HeaderLength  = 20
)

var (
	snapshot_len int32 = 1500
	promiscuous  bool  = true
)

func captureToFile(device string, fileName string, timeoutSeconds int) error {
	// timeout := int64(timeoutSeconds) * time.Second
	tcpdumpCmd := exec.Command("sudo", "tcpdump", "-i", device,
		"-G", fmt.Sprintf("%d", timeoutSeconds),
		"-W", "1", "-w", fileName)

	err := tcpdumpCmd.Run()
	return err
}

func CaptureTCPPacket(device string, srcNet *net.IPNet, dstNet *net.IPNet,
	srcPort uint16, dstPort uint16, timeout time.Duration) (bool, error) {
	if srcNet == nil || dstNet == nil {
		return false, fmt.Errorf("invalid src network or dst network")
	}
	tcpdumpFile := "/tmp/tcp.pcap"
	timeoutSeconds := int(math.Ceil(timeout.Seconds()))
	err := captureToFile(device, tcpdumpFile, timeoutSeconds)
	if err != nil {
		return false, err
	}
	handle, err := pcap.OpenOffline(tcpdumpFile)
	if err != nil {
		return false, err
	}

	var capturedData []byte
	timeStart := time.Now()
	for err == nil {
		capturedData, _, err = handle.ReadPacketData()
		if err != nil {
			return false, err
		}
		_, ipLayer, tcpLayer, e := decodeTCPFromBytes(capturedData)
		if e == nil {
			if srcNet.Contains(ipLayer.SrcIP) && dstNet.Contains(ipLayer.DstIP) &&
				(srcPort == 0 || srcPort == uint16(tcpLayer.SrcPort)) &&
				(dstPort == 0 || dstPort == uint16(tcpLayer.DstPort)) {
				fmt.Printf("got target packet\n")
				return true, nil
			}
		}
	}
	defer func() {
		fmt.Printf("spent %v to parse packets\n", time.Now().Sub(timeStart))
	}()
	return false, nil
}

func CaptureIPIPPacket(device string, srcNet *net.IPNet, dstNet *net.IPNet,
	srcNetInner *net.IPNet, dstNetInner *net.IPNet, timeout time.Duration) (bool, error) {
	if srcNet == nil || dstNet == nil || srcNetInner == nil || dstNetInner == nil {
		return false, fmt.Errorf("invalid src network or dst network")
	}

	tcpdumpFile := "/tmp/ipip.pcap"
	timeoutSeconds := int(math.Ceil(timeout.Seconds()))
	err := captureToFile(device, tcpdumpFile, timeoutSeconds)
	if err != nil {
		return false, err
	}
	handle, err := pcap.OpenOffline(tcpdumpFile)
	if err != nil {
		return false, err
	}

	var capturedData []byte
	for err == nil {
		capturedData, _, err = handle.ReadPacketData()
		if err != nil {
			return false, err
		}
		_, ipLayer, ipLayerInner, e := decodeIPIPFromBytes(capturedData)
		if e == nil {
			if srcNet.Contains(ipLayer.SrcIP) && dstNet.Contains(ipLayer.DstIP) &&
				srcNetInner.Contains(ipLayerInner.SrcIP) && dstNetInner.Contains(ipLayerInner.DstIP) {
				fmt.Printf("got target packet\n")
				return true, nil
			}
		}
	}

	return false, nil

}

func decodeTCPFromBytes(data []byte) (*layers.Ethernet, *layers.IPv4, *layers.TCP, error) {
	var err error
	etherLayer := &layers.Ethernet{}
	err = etherLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, nil, nil, err
	}
	if etherLayer.EthernetType != layers.EthernetTypeIPv4 {
		return etherLayer, nil, nil, fmt.Errorf("ethertype is %v, not IPv4", etherLayer.EthernetType)
	}
	ipLayer := &layers.IPv4{}
	headerLen := etherHeaderLength
	err = ipLayer.DecodeFromBytes(data[headerLen:], gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, nil, nil, err
	}
	if ipLayer.Protocol != layers.IPProtocolTCP {
		return etherLayer, ipLayer, nil, fmt.Errorf("IP Protocol is %v, not TCP", ipLayer.Protocol)
	}
	tcpLayer := &layers.TCP{}
	headerLen = etherHeaderLength + ipv4HeaderLength
	err = tcpLayer.DecodeFromBytes(data[headerLen:], gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, nil, nil, err
	}
	return etherLayer, ipLayer, tcpLayer, nil
}

func decodeIPIPFromBytes(data []byte) (*layers.Ethernet, *layers.IPv4, *layers.IPv4, error) {
	var err error
	etherLayer := &layers.Ethernet{}
	err = etherLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, nil, nil, err
	}
	if etherLayer.EthernetType != layers.EthernetTypeIPv4 {
		return etherLayer, nil, nil, fmt.Errorf("ethertype is %v, not IPv4", etherLayer.EthernetType)
	}
	ipLayer := &layers.IPv4{}
	headerLen := etherHeaderLength
	err = ipLayer.DecodeFromBytes(data[headerLen:], gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, nil, nil, err
	}
	if ipLayer.Protocol != layers.IPProtocolIPv4 {
		return etherLayer, ipLayer, nil, fmt.Errorf("IP Protocol is %v, not IPIP", ipLayer.Protocol)
	}
	ipLayerInner := &layers.IPv4{}
	headerLen = etherHeaderLength + ipv4HeaderLength
	err = ipLayerInner.DecodeFromBytes(data[headerLen:], gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, nil, nil, err
	}
	return etherLayer, ipLayer, ipLayerInner, nil
}
