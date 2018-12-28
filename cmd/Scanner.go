package cmd

import (
	"fmt"
 	"strings"
 	"os/exec"
	"bufio"
	"sync"
	"os"
	"github.com/fatih/color"
)

/* This recursive function extracts IP addresses from nmap -sn output. The function gets command's output and a slice of target IPs. 
It returns slice of target IPs updated (appended) */
func ExtractIPs(sliceOfTargets []string, nmapCmdOutput string) []string {
	var forWord string = "for"
	forWordIndex := strings.Index(nmapCmdOutput, forWord)
	if forWordIndex != -1 {
		nmapOutTrimmed := nmapCmdOutput[forWordIndex+4:]
		hostWordIndex := strings.Index(nmapOutTrimmed, "Host")
		aliveHostAddress := nmapOutTrimmed[:hostWordIndex]
		nmapOutTrimmed = strings.Replace(nmapOutTrimmed, aliveHostAddress, "\n", -1) 
		sliceOfTargets = append(sliceOfTargets, aliveHostAddress)
		return ExtractIPs(sliceOfTargets, nmapOutTrimmed) 
	} else {
		return sliceOfTargets 
	}		 			
}


/* This function gets empty slice of target IPs and attacker's IP address. 
It identifies targets in his current subnet, saves those addresses in a slice of targets,prints them and return them. */
func AliveHostsInSubnet(ipAddressesSlice []string, myIpAddress string) []string {
	var dots, thirdDotIndex int
	var dot string = "."
	for i := range myIpAddress {
		if (string(myIpAddress[i]) == dot) && (dots <= 2) {
			dots++ }
		if (string(myIpAddress[i]) == dot) && (dots == 3) {
			thirdDotIndex = i }
   	}
	subnetToScan := myIpAddress[:thirdDotIndex] + dot + "0"
	nmapCmd := exec.Command("bash", "-c", "sudo nmap -sn -T4 " + subnetToScan + "/24")
    	nmapOut, err := nmapCmd.Output()
    	if err != nil {
        	panic(err)
    	}
    	fmt.Println(" ")
	nmapOutput := string(nmapOut)
	targets := ExtractIPs(ipAddressesSlice, nmapOutput)
	color.White("[+] Alive hosts in " + subnetToScan + "/24 are:\n\n")
	for k := range targets {
		fmt.Println(targets[k])
   	}
	return targets
} 


/* This function gets empty slice of target IPs and attacker's IP address. 
It identifies targets in all subnets, saves those addresses in a slice of targets,prints them and return them. */
func AliveHostsInAllSubnets(ipAddressesSlice []string, myIpAddress string) []string {
	var dots, thirdDotIndex int
	var dot string = "."
	for i := range myIpAddress {
		if (string(myIpAddress[i]) == dot) && (dots <= 2) {
			dots++ }
		if (string(myIpAddress[i]) == dot) && (dots == 3) {
			thirdDotIndex = i }
   	}
	subnetToScan := myIpAddress[:thirdDotIndex] + dot + "0"
	nmapCmd := exec.Command("bash", "-c", "sudo nmap -sn -T4 " + subnetToScan + "/16")
    	nmapOut, err := nmapCmd.Output()
    	if err != nil {
        	panic(err)
    	}
    	fmt.Println(" ")
	nmapOutput := string(nmapOut)
	targets := ExtractIPs(ipAddressesSlice, nmapOutput)
	color.White("[+] Alive hosts in " + subnetToScan + "/24 are:\n")
	for k := range targets {
		fmt.Println(targets[k])
   	}
	return targets
} 

/* This function performs a nmap TCP script scan on target IP. */
func TCPScan(targetIP string, outputPath string, workgroup *sync.WaitGroup) {
	color.Green("\n\n[!] Starting to scan " + targetIP + " for TCP interesting stuff.\n\n")
	nmapCmd := exec.Command("bash", "-c", "nmap -p- -A -T4 -Pn -vv -oG " + outputPath + "/nmap_tcp_scan_output_grepable > " + outputPath + "/nmap_tcp_scan_output " + targetIP)
    	err := nmapCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	color.White("\n\n[+] Nmap's TCP script scanning on " + targetIP + " is completed successfully.\n\n")
	color.Green("\n\n[!] Starting to scan " + targetIP + " for web application vulnerabilities.\n\n")
	niktoCmd := exec.Command("bash", "-c", "nikto -h " + outputPath + "/nmap_tcp_scan_output_grepable -Tuning x12567> " + outputPath + "/nikto_scan_out.txt")
    	err = niktoCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	color.White("\n\n[+] Nikto's scan on " + targetIP + " is completed successfully.\n\n")
	workgroup.Done()
}

/* This function performs a nmap UDP script scan on target IP. */
func UDPScan(targetIP string, outputPath string, workgroup *sync.WaitGroup) {
	color.Green("\n\n[!] Starting to scan " + targetIP + " for UDP interesting stuff.\n\n")
	nmapCmd := exec.Command("bash", "-c", "nmap -sU -p- -A -T4 -Pn -vv > " + outputPath + "/nmap_udp_scan_output " + targetIP)
    	err := nmapCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	color.White("\n\n[+] Nmap's UDP script scanning on " + targetIP + " is completed successfully.\n\n")
	workgroup.Done()
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

