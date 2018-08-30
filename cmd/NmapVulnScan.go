package cmd

import (
	"fmt"
 	"os/exec"
	//"io/ioutil"
	"bufio"
	//"os"
	"strings"
)


/* This function performs a basic nmap TCP scan on target IP. */
func NmapTCPScan(targetIP string, xmlPath string) {
	fmt.Println("\n\n[!] Starting to scan " + targetIP + " for TCP ports.\n")
	nmapCmd := exec.Command("bash", "-c", "sudo nmap -sS -p- -T4 -Pn -vv -oX " + xmlPath + "/TCPxml " + targetIP)
    	err := nmapCmd.Start()
    	if err != nil {
        	panic(err)
    	}
	err = nmapCmd.Wait()	
	if err != nil {
        	panic(err)
    	}
}

/* This function performs a basic nmap UDP scan on target IP. */
func NmapUDPScan(targetIP string, xmlPath string) {
	fmt.Println("\n\n[!] Starting to scan " + targetIP + " for UDP ports.\n")
	nmapCmd := exec.Command("bash", "-c", "sudo nmap -sU -p- -T4 -Pn -vv -oX " + xmlPath + "/UDPxml " + targetIP)
    	err := nmapCmd.Start()
    	if err != nil {
        	panic(err)
    	}
	err = nmapCmd.Wait()	
	if err != nil {
        	panic(err)
    	}
}

/* This function gets nmap's xml file as a string and returns a slice of TCP or UDP ports that are mentioned inside. */
func PortExtractor(p string) {			//see extractips func
	/* xmlFile, err := os.Open(p)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("[!] Successfully opened: " + p)
	bytes, _ := ioutil.ReadAll(xmlFile)
	defer xmlFile.Close()
	xml := string(bytes) */
	cutEnd := ">"
	portidWordIndex := strings.Index(p, "portid=")
	cutEndIndex := portidWordIndex
	fmt.Println("portidWordIndex: ", portidWordIndex)
	cutEndIndex = strings.Index(p, cutEnd)
	//fmt.Println("cutEndIndex: ", cutEndIndex)
	fmt.Println("p:\n",p)
	scanner := bufio.NewScanner(p)
	for p.Scan() {
		if portidWordIndex != -1 {
			portValue := p[portidWordIndex+7:cutEndIndex]
			fmt.Println("portid value: ", portValue)	
		}
	}
	//fmt.Println("portidWordIndex: ", portidWordIndex)
	//fmt.Println("portid value: ", portidWordIndex+7)


	/* for scanner.Scan() {
		if strings.Contains(scanner.Text(), "portid=") {
			portidWordIndex := strings.Index(string(bytes), "portid=")
			fmt.Println("portidWordIndex: ", portidWordIndex)
			fmt.Println("portid value: ", portidWordIndex+7)
	    }    
	}
	if err := scanner.Err(); err != nil {
	    fmt.Println("There is an error scanning " + p + " ",err)
	} */
}
	
/* This function performs a nmap vulnerability scan against TCP/UDP ports that were discovered in previews scans. */
func NmapVulnScan(targetIP string, xmlPath string, tcpPorts string, udpPorts string) {
	fmt.Println("\n\n[!] Starting to scan " + targetIP + " for vulnerabilities.\n")
	nmapCmd := exec.Command("bash", "-c", "sudo nmap -Pn -sV -A -pT:" + tcpPorts + ",U:" + udpPorts + " -script vuln -vv -oX " + xmlPath + "/Vulns " + targetIP)
    	err := nmapCmd.Start()
    	if err != nil {
        	panic(err)		
    	}
	err = nmapCmd.Wait()	
	if err != nil {
        	panic(err)
    	}
}

