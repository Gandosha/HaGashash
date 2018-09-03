package cmd

import (
	"fmt"
 	"os/exec"
	"unicode"
	//"bufio"
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

/* This recursive function gets nmap's xml file as a string and returns a slice of TCP or UDP ports that are mentioned inside. */
func PortExtractor(p string, sliceOfPorts []string) []string{			
	portidWordIndex := strings.Index(p, "portid=")
	if portidWordIndex != -1 {
		portidValue := p[portidWordIndex+8:portidWordIndex+13]
		portidValue = strings.TrimRightFunc(portidValue, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r)})
		sliceOfPorts = append(sliceOfPorts, portidValue)
		p = p[portidWordIndex+14:] 
		return PortExtractor(p, sliceOfPorts)
	} else {
		return sliceOfPorts 
	}	
	
}
	
/* This function performs a nmap vulnerability scan against TCP/UDP ports that were discovered. */
func NmapVulnScan(targetIP string, ports []string, nativ string, protocol string) {
	fmt.Println("targetIP: \n",targetIP)
	fmt.Println("nativ: \n",nativ)
	fmt.Println("protocol: \n",protocol)
	portss := strings.Join(ports, ",")
	fmt.Println("Portss: \n",portss)
	switch {
		case protocol == "TCP": 
			fmt.Println("\n\n[!] Starting to scan " + targetIP + " for TCP ports vulnerabilities.")
			nmapCmd := exec.Command("bash", "-c", "sudo nmap -Pn -sV -A -pT:" + portss + " -script vuln -vv " + targetIP + " > " + nativ + "/TCP_Vulns" )
		    	err := nmapCmd.Start()
		    	if err != nil {
				panic(err)		
		    	}
			err = nmapCmd.Wait()	
			if err != nil {
				panic(err)
		    	}
			fmt.Println("[!] Nmap TCP vulnerability scanning for " + targetIP + " is completed successfully.")
		case protocol == "UDP": 
			fmt.Println("\n\n[!] Starting to scan " + targetIP + " for UDP ports vulnerabilities.")
			nmapCmd := exec.Command("bash", "-c", "sudo nmap -Pn -sV -A -pU:" + portss + " -script vuln -vv " + targetIP + " > " + nativ + "/UDP_Vulns" )
		    	err := nmapCmd.Start()
		    	if err != nil {
				panic(err)		
		    	}
			err = nmapCmd.Wait()	
			if err != nil {
				panic(err)
		    	}
			fmt.Println("[!] Nmap UDP vulnerability scanning for " + targetIP + " is completed successfully.")
		} 
}

