package cmd

import (
 	"os/exec"
	"unicode"
	"strings"
	"bufio"
	"os"
	"github.com/fatih/color"
)


/* This function performs a basic nmap TCP scan on target IP. */
func NmapTCPScan(targetIP string, xmlPath string) {
	color.Green("\n\n[!] Starting to scan " + targetIP + " for TCP ports.\n\n")
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
	color.Green("\n\n[!] Starting to scan " + targetIP + " for UDP ports.\n\n")
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
	portss := strings.Join(ports, ",")
	switch {
		case protocol == "TCP": 
			color.Green("\n\n[!] Starting to scan " + targetIP + " for TCP ports vulnerabilities.\n\n")
			nmapCmd := exec.Command("bash", "-c", "sudo nmap -Pn -sV -A -pT:" + portss + " -script vuln -vv " + targetIP + " -oN " + nativ + "/TCP_Vulns")
		    	err1 := nmapCmd.Start()
		    	if err1 != nil {
				panic(err1)		
		    	}
			err2 := nmapCmd.Wait()	
			if err2 != nil {
				panic(err2)
		    	}
			color.Cyan("\n\n[!] Nmap TCP vulnerability scanning for " + targetIP + " is completed successfully.\n\n")
		case protocol == "UDP": 
			color.Green("\n\n[!] Starting to scan " + targetIP + " for UDP ports vulnerabilities.\n\n")
			nmapCmd := exec.Command("bash", "-c", "sudo nmap -Pn -sV -A -pU:" + portss + " -script vuln -vv " + targetIP + " -oN " + nativ + "/UDP_Vulns")
		    	err1 := nmapCmd.Start()
		    	if err1 != nil {
				panic(err1)		
		    	}
			err2 := nmapCmd.Wait()	
			if err2 != nil {
				panic(err2)
		    	}
			color.Cyan("\n\n[!] Nmap UDP vulnerability scanning for " + targetIP + " is completed successfully.\n\n")
		} 
}

/* This function reads the content of a file and returns a slice of hosts that are mentioned there (the addresses inside the file should be Line-By-Line). */
func ReadLine(pathPtr string) []string {
	var sliceOfHosts []string
  	inFile, _ := os.Open(pathPtr)
  	defer inFile.Close()
  	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
  	for scanner.Scan() {
		sliceOfHosts = append(sliceOfHosts, scanner.Text())
  	}
	return sliceOfHosts
}

