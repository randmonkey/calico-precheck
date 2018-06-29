package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type HostInfo struct {
	hostName         string
	hostIP           string
	hostSSHPort      uint16
	hostMAC          string
	hostNetInterface string
	hostUsername     string
}

func execCommandOnHost(username string, host string, port uint16, command []string) (
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
		log.Fatalf("failed to parse host file %s, error %v", hostFilePath, err)
	}
	for host, hostInfo := range hostInfoMap {
		for otherHost, otherHostInfo := range hostInfoMap {
			if host != otherHost {
				fmt.Printf("=== check connectivity from %s to %s ===\n", host, otherHost)
				passed, _ := checkConnectivity(hostInfo, otherHostInfo)
				if passed {
					fmt.Printf("%s to %s: OK\n", host, otherHost)
				} else {
					fmt.Printf("%s to %s: failed, see above to get details", host, otherHost)
				}
				fmt.Printf("===============================================\n")
			}
		}

	}

}

func checkConnectivity(hostInfo, otherHostInfo *HostInfo) (bool, error) {
	if hostInfo == nil || otherHostInfo == nil {
		return false, fmt.Errorf("host info not provided")
	}
	allOK := true
	// check L3 connectivity by ping
	_, _, err := execCommandOnHost(hostInfo.hostUsername, hostInfo.hostIP, hostInfo.hostSSHPort,
		[]string{
			"ping",
			"-c3",
			otherHostInfo.hostIP,
		})
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), ping test failed\n",
			hostInfo.hostName, hostInfo.hostIP, otherHostInfo.hostName, otherHostInfo.hostIP)
	}

	// check TCP ports for BGP, etcd, and kubernetes API server
	// check BGP...
	_, _, err = execCommandOnHost(hostInfo.hostUsername, hostInfo.hostIP, hostInfo.hostSSHPort,
		[]string{
			"sudo",
			"/tmp/tcp-send",
			fmt.Sprintf("-dst-ip=%s", otherHostInfo.hostIP),
			fmt.Sprintf("-dst-mac=%s", otherHostInfo.hostMAC),
			fmt.Sprintf("-dev=%s", hostInfo.hostNetInterface),
			fmt.Sprintf("-dst-port=%d", 179),
		})
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), tcp port %d for BGP not OK\n",
			hostInfo.hostName, hostInfo.hostIP, otherHostInfo.hostName, otherHostInfo.hostIP, 179)
	}

	// check etcd port
	_, _, err = execCommandOnHost(hostInfo.hostUsername, hostInfo.hostIP, hostInfo.hostSSHPort,
		[]string{
			"sudo",
			"/tmp/tcp-send",
			fmt.Sprintf("-dst-ip=%s", otherHostInfo.hostIP),
			fmt.Sprintf("-dst-mac=%s", otherHostInfo.hostMAC),
			fmt.Sprintf("-dev=%s", hostInfo.hostNetInterface),
			fmt.Sprintf("-dst-port=%d", etcdPort),
		})
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), tcp port %d for etcd not OK\n",
			hostInfo.hostName, hostInfo.hostIP, otherHostInfo.hostName, otherHostInfo.hostIP, etcdPort)
	}

	// check kube-api port
	_, _, err = execCommandOnHost(hostInfo.hostUsername, hostInfo.hostIP, hostInfo.hostSSHPort,
		[]string{
			"sudo",
			"/tmp/tcp-send",
			fmt.Sprintf("-dst-ip=%s", otherHostInfo.hostIP),
			fmt.Sprintf("-dst-mac=%s", otherHostInfo.hostMAC),
			fmt.Sprintf("-dev=%s", hostInfo.hostNetInterface),
			fmt.Sprintf("-dst-port=%d", kubeapiPort),
		})
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), tcp port %d for kubernetes APIserver not OK\n",
			hostInfo.hostName, hostInfo.hostIP, otherHostInfo.hostName, otherHostInfo.hostIP, kubeapiPort)
	}

	// check IPIP connectivity by sending IPIP packet
	_, _, err = execCommandOnHost(
		hostInfo.hostUsername, hostInfo.hostIP, hostInfo.hostSSHPort,
		[]string{
			"sudo",
			"/tmp/ipip-send",
			fmt.Sprintf("-dst-ip=%s", otherHostInfo.hostIP),
			fmt.Sprintf("-dst-mac=%s", otherHostInfo.hostMAC),
			fmt.Sprintf("-dev=%s", hostInfo.hostNetInterface),
		},
	)
	if err != nil {
		allOK = false
		fmt.Printf("%s(%s) To %s(%s), IPIP check failed\n",
			hostInfo.hostName, hostInfo.hostIP, otherHostInfo.hostName, otherHostInfo.hostIP)
	}
	return allOK, nil
}
