package cmd

import (
	"fmt"
 	"os/exec"
 	"strings"
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
It identifies targets in his current subnet, saves those addresses in a slice of target and prints them. */
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
	nmapCmd := exec.Command("bash", "-c", "sudo nmap -sn " + subnetToScan + "/24")
    	nmapOut, err := nmapCmd.Output()
    	if err != nil {
        	panic(err)
    	}
    	fmt.Println(" ")
	nmapOutput := string(nmapOut)
	targets := ExtractIPs(ipAddressesSlice, nmapOutput)
	fmt.Println("[+] Alive hosts in " + subnetToScan + "/24 are:\n")
	for k := range targets {
		fmt.Println(targets[k])
   	}
	return targets
} 