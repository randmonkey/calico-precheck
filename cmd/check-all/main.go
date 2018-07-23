package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
)

type HostInfo struct {
	hostName         string
	hostIP           string
	hostSSHPort      uint16
	hostMAC          string
	hostNetInterface string
	hostUsername     string
}

func execCommandOnHost(username string, host string, port uint16, command []string,
	errCh chan error) (
	stdOut string, stdErr string, err error) {
	sshCommand := []string{
		username + "@" + host,
		"-p",
		fmt.Sprintf("%d", port),
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	sshCommand = append(sshCommand, command...)
	cmd := exec.Command("ssh", sshCommand...)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf
	err = cmd.Run()
	stdoutBytes, _ := ioutil.ReadAll(stdoutBuf)
	stderrBytes, _ := ioutil.ReadAll(stderrBuf)
	errCh <- err
	close(errCh)
	return string(stdoutBytes), string(stderrBytes), err
}

func parseHostFile(hostFilePath string) (map[string]*HostInfo, error) {
	hostFile, err := os.OpenFile(hostFilePath, os.O_RDONLY, 0400)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(hostFile)
	scanner.Split(bufio.ScanLines)
	hosts := make(map[string]*HostInfo)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) < 6 {
			continue
		}
		sshPort, parseErr := strconv.ParseUint(parts[3], 10, 16)
		if parseErr != nil {
			fmt.Printf("parse ssh port for %s error: %v", parts[3], err)
			sshPort = 22
		}
		hostInfo := &HostInfo{
			hostName:         parts[0],
			hostUsername:     parts[1],
			hostIP:           parts[2],
			hostSSHPort:      uint16(sshPort),
			hostMAC:          parts[4],
			hostNetInterface: parts[5],
		}
		hosts[hostInfo.hostName] = hostInfo
	}
	return hosts, nil

}

var (
	hostFilePath string
	bgpPort      = 179
	etcdPort     int
	kubeapiPort  int
)

func main() {
	flag.StringVar(&hostFilePath, "f", "",
		"path of file containing name, IP, MAC, and interface device name of hosts")
	flag.IntVar(&etcdPort, "etcd-port", 2379, "port listened by etcd")
	flag.IntVar(&kubeapiPort, "kube-api-port", 6443, "port listened by kunernetes API server")
	flag.Parse()
	hostInfoMap, err := parseHostFile(hostFilePath)
	if err != nil {
		glog.Fatalf("failed to parse host file %s, error %v", hostFilePath, err)
	}
	for host, hostInfo := range hostInfoMap {
		fmt.Printf("==== check host %s ====\n", host)
		passed := true
		for otherHost, otherHostInfo := range hostInfoMap {
			if host != otherHost {
				fmt.Printf("=== check connectivity from %s to %s ===\n", host, otherHost)
				connectivityOK, _ := checkConnectivity(hostInfo, otherHostInfo)
				if connectivityOK {
					fmt.Printf("connectivity from %s to %s: OK\n", host, otherHost)
				} else {
					fmt.Printf(
						"connectivity from %s to %s: failed, see above to get details\n",
						host, otherHost)
				}
				passed = passed && connectivityOK
			}
		}
		systemVarOK := checkSystemVars(hostInfo)
		if systemVarOK {
			fmt.Printf("system settings on %s OK\n", host)
		} else {
			fmt.Printf("system settings on %s not OK\n", host)
		}
		passed = passed && systemVarOK
		if passed {
			fmt.Printf("====== host %s OK ======\n", host)
		} else {
			fmt.Printf("====== host %s not OK, see above for details\n", host)
		}

	}

}

func checkSystemVars(hostInfo *HostInfo) bool {
	if hostInfo == nil {
		return false
	}
	stdout, _, err := execCommandOnHost(hostInfo.hostUsername, hostInfo.hostIP, hostInfo.hostSSHPort,
		[]string{
			"sudo",
			"sysctl",
			"net.ipv4.ip_forward",
		},
		make(chan error, 1))
	if err != nil {
		fmt.Printf("failed to check system configuration net.ipv4.ip_forward on %s(%s)\n",
			hostInfo.hostName, hostInfo.hostIP)
		return false
	}
	if strings.Contains(stdout, "= 1") {
		return true
	} else {
		fmt.Printf("net.ipv4.ip_forward is not opened on %s(%s)\n",
			hostInfo.hostName, hostInfo.hostIP)
		return false
	}
	return false
}

func checkConnectivity(hostInfo, otherHostInfo *HostInfo) (bool, error) {
	if hostInfo == nil || otherHostInfo == nil {
		return false, fmt.Errorf("host info not provided")
	}
	allOK := true
	// check L3 connectivity by ping
	glog.V(1).Infof("cheking IP connectivity from %s to %s...",
		hostInfo.hostName, otherHostInfo.hostName)
	_, _, err := execCommandOnHost(hostInfo.hostUsername, hostInfo.hostIP, hostInfo.hostSSHPort,
		[]string{
			"ping",
			"-c3",
			otherHostInfo.hostIP,
		}, make(chan error, 1))
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), ping test failed\n",
			hostInfo.hostName, hostInfo.hostIP, otherHostInfo.hostName, otherHostInfo.hostIP)
	}
	glog.V(1).Infof("checking TCP ports from %s to %s...",
		hostInfo.hostName, otherHostInfo.hostName)
	// check TCP ports for BGP, etcd, and kubernetes API server
	// check BGP...
	err = checkTCPPort(hostInfo, otherHostInfo, uint16(bgpPort))
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), tcp port %d for BGP not OK\n",
			hostInfo.hostName, hostInfo.hostIP,
			otherHostInfo.hostName, otherHostInfo.hostIP, bgpPort)
	}

	// check etcd port
	err = checkTCPPort(hostInfo, otherHostInfo, uint16(etcdPort))
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), tcp port %d for etcd not OK\n",
			hostInfo.hostName, hostInfo.hostIP,
			otherHostInfo.hostName, otherHostInfo.hostIP, etcdPort)
	}

	// check kube-api port
	err = checkTCPPort(hostInfo, otherHostInfo, uint16(kubeapiPort))
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), tcp port %d for kubernetes APIserver not OK\n",
			hostInfo.hostName, hostInfo.hostIP,
			otherHostInfo.hostName, otherHostInfo.hostIP, kubeapiPort)
	}

	// check IPIP connectivity by sending IPIP packet
	glog.V(1).Infof("checking IPIP connectivity from %s to %s...",
		hostInfo.hostName, otherHostInfo.hostName)
	err = checkIPIP(hostInfo, otherHostInfo)
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), IPIP check failed\n",
			hostInfo.hostName, hostInfo.hostIP, otherHostInfo.hostName, otherHostInfo.hostIP)
	}
	return allOK, nil
}

func checkTCPPort(hostInfo, otherHostInfo *HostInfo, targetPort uint16) error {
	sendErrChan := make(chan error, 1)
	captureErrChan := make(chan error, 1)
	var err error
	go func() {
		stdout, stderr, _ := execCommandOnHost(
			otherHostInfo.hostUsername, otherHostInfo.hostIP, otherHostInfo.hostSSHPort, []string{
				"sudo",
				"/tmp/capture-packet",
				"-proto=tcp",
				fmt.Sprintf("-dev=%s", otherHostInfo.hostNetInterface),
				fmt.Sprintf("-src-ip=%s", hostInfo.hostIP),
				fmt.Sprintf("-dst-ip=%s", otherHostInfo.hostIP),
				fmt.Sprintf("-dst-port=%d", targetPort),
				"-timeout=5s",
			}, captureErrChan)
		glog.V(2).Infof("stdout of capturing packets: %s\n", stdout)
		glog.V(2).Infof("stderr of capturing packets: %s\n", stderr)
	}()
	time.Sleep(100 * time.Millisecond)
	go func() {
		stdout, stderr, _ := execCommandOnHost(hostInfo.hostUsername, hostInfo.hostIP, hostInfo.hostSSHPort,
			[]string{
				"sudo",
				"/tmp/tcp-send",
				fmt.Sprintf("-dst-ip=%s", otherHostInfo.hostIP),
				fmt.Sprintf("-dst-mac=%s", otherHostInfo.hostMAC),
				fmt.Sprintf("-dev=%s", hostInfo.hostNetInterface),
				fmt.Sprintf("-dst-port=%d", targetPort),
			}, sendErrChan)
		glog.V(2).Infof("stdout of sending packets: %s\n", stdout)
		glog.V(2).Infof("stderr of sending packets: %s\n", stderr)

	}()
	err = <-captureErrChan
	return err
}

func checkIPIP(hostInfo, otherHostInfo *HostInfo) error {
	sendErrChan := make(chan error, 1)
	captureErrChan := make(chan error, 1)
	var err error
	go func() {
		stdout, stderr, _ := execCommandOnHost(
			otherHostInfo.hostUsername, otherHostInfo.hostIP, otherHostInfo.hostSSHPort, []string{
				"sudo",
				"/tmp/capture-packet",
				"-proto=ipip",
				fmt.Sprintf("-dev=%s", otherHostInfo.hostNetInterface),
				fmt.Sprintf("-src-ip=%s", hostInfo.hostIP),
				fmt.Sprintf("-dst-ip=%s", otherHostInfo.hostIP),
				fmt.Sprintf("-src-ip-inner=%s", hostInfo.hostIP),
				fmt.Sprintf("-dst-ip-inner=%s", otherHostInfo.hostIP),
				"-timeout=5s",
			}, captureErrChan)
		glog.V(2).Infof("stdout of capturing packets: %s\n", stdout)
		glog.V(2).Infof("stderr of capturing packets: %s\n", stderr)
	}()
	time.Sleep(100 * time.Millisecond)
	go func() {
		stdout, stderr, _ := execCommandOnHost(
			hostInfo.hostUsername, hostInfo.hostIP, hostInfo.hostSSHPort,
			[]string{
				"sudo",
				"/tmp/ipip-send",
				fmt.Sprintf("-dst-ip=%s", otherHostInfo.hostIP),
				fmt.Sprintf("-dst-mac=%s", otherHostInfo.hostMAC),
				fmt.Sprintf("-dev=%s", hostInfo.hostNetInterface),
			}, sendErrChan)
		glog.V(2).Infof("stdout of sending packets: %s\n", stdout)
		glog.V(2).Infof("stderr of sending packets: %s\n", stderr)
	}()

	err = <-captureErrChan
	return err
}
