package cmd

import (
	"fmt"
 	"os/exec"
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

