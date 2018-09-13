package cmd

import (
 	"os/exec"
	"unicode"
	"strings"
	"bufio"
	"sync"
	"os"
	"fmt"
	"io/ioutil"
	"github.com/fatih/color"
)


/* This function performs a nmap TCP vulnerability scan on target IP. */
func NmapTCPScan(targetIP string, xmlPath string, workgroup *sync.WaitGroup) {
	color.Green("\n\n[!] Starting to scan " + targetIP + " for TCP ports.\n\n")
	var tarsTCPorts []string
	nmapCmd := exec.Command("bash", "-c", "nmap -sS -p- -T4 -Pn -vv -oX " + xmlPath + "/TCPxml " + targetIP)
    	err := nmapCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	//Open up the xml and extract TCP ports from it
	path := xmlPath + "/TCPxml"
	xmlFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
	}
	bytes, _ := ioutil.ReadAll(xmlFile)
	defer xmlFile.Close()
	xml := string(bytes)
	tarsTCPorts = PortExtractor(xml, tarsTCPorts)
	ports := strings.Join(tarsTCPorts, ",")
	switch {
		case len(ports) > 0:
			//Scan extracted ports for vulns
			color.Green("\n\n[!] Starting to scan " + targetIP + " for TCP ports vulnerabilities.\n\n")
			nmapVulnCmd := exec.Command("bash", "-c", "nmap -Pn -sV -A -pT:" + ports + " -script vuln -vv " + targetIP + " -oN " + xmlPath + "/TCP_Vulns")
		    	err = nmapVulnCmd.Run()
		    	if err != nil {
				panic(err)		
		    	}
			color.Cyan("\n\n[!] Nmap TCP vulnerability scanning for " + targetIP + " is completed successfully.\n\n")
		case len(ports) == 0:
			workgroup.Done()
	}
}

/* This function performs a nmap UDP vulnerability scan on target IP. */
func NmapUDPScan(targetIP string, xmlPath string, workgroup *sync.WaitGroup) {
	color.Green("\n\n[!] Starting to scan " + targetIP + " for UDP ports.\n\n")
	var tarsUDPorts []string
	nmapCmd := exec.Command("bash", "-c", "nmap -sU -p- -T4 -Pn -vv -oX " + xmlPath + "/UDPxml " + targetIP)
    	err := nmapCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	//Open up the xml and extract UDP ports from it
	path := xmlPath + "/UDPxml"
	xmlFile, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
	}
	bytes, _ := ioutil.ReadAll(xmlFile)
	defer xmlFile.Close()
	xml := string(bytes)
	tarsUDPorts = PortExtractor(xml, tarsUDPorts)
	ports := strings.Join(tarsUDPorts, ",")
	switch {
		case len(ports) > 0:
			//Scan extracted ports for vulns
			color.Green("\n\n[!] Starting to scan " + targetIP + " for UDP ports vulnerabilities.\n\n")
			nmapVulnCmd := exec.Command("bash", "-c", "nmap -Pn -sV -A -pU:" + ports + " -script vuln -vv " + targetIP + " -oN " + xmlPath + "/UDP_Vulns")
		    	err = nmapVulnCmd.Run()
		    	if err != nil {
				panic(err)		
		    	}
			color.Cyan("\n\n[!] Nmap UDP vulnerability scanning for " + targetIP + " is completed successfully.\n\n")
		case len(ports) == 0:
			workgroup.Done()
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

