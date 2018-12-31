package cmd

import (
	"fmt"
 	"strings"
 	"os/exec"
	"bufio"
	"sync"
	"github.com/fatih/color"
	"os"
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


/* This function gets an empty slice of target IPs and attacker's IP address. 
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

/* This function performs a nmap TCP script scan on target IP.
It initiates PortExtractor and WebScan function against the target. */
func TCPScan(targetIP string, outputPath string, workgroup *sync.WaitGroup) {
	var (
		sliceOfPorts []string	//slice of ports per service
		service2export string
		serviceNameIndex int
	)
	color.Green("\n\n[!] Starting to scan " + targetIP + " for TCP interesting stuff.\n\n")
	nmapCmd := exec.Command("bash", "-c", "nmap -p- -A -T4 -Pn -vv -oG " + outputPath + "/nmap_tcp_scan_output_grepable > " + outputPath + "/nmap_tcp_scan_output " + targetIP)
    	err := nmapCmd.Run()
    	if err != nil {
        	panic(err)
    	}	
	color.White("\n\n[+] Nmap's TCP script scanning on " + targetIP + " is completed successfully.\n\n")
	//PortExtractor
	service2export = "http"
	grepable := OpenFile2Read(outputPath + "/nmap_tcp_scan_output_grepable")
	serviceNameIndex = strings.Index(grepable, service2export)	//Find service's name index
	if ( serviceNameIndex != -1 ) {
		answer, portnum, dat := PortExtractor(grepable, service2export)
		sliceOfPorts = append(sliceOfPorts,portnum)
		for answer {
			answer, portnum, dat = PortExtractor(dat,service2export)
			sliceOfPorts = append(sliceOfPorts,portnum)
		}
		fmt.Printf("\n\nsliceOfPorts:\n",sliceOfPorts)
		//WebScan on extracted ports
		for _, port := range sliceOfPorts {
			WebScan(targetIP, outputPath, port)
		}
	}
	color.Red("\n\n[+] TCP scan on " + targetIP + " is completed successfully.\n\n")
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

/* This function performs a web application vulnerability scan against target IP. */
func WebScan(targetIP string, outputPath string, port2scan string) {
	color.Green("\n\n[!] Starting to scan " + targetIP + ":" + port2scan + " for web application vulnerabilities.\n\n")
	//Initiate cewl on targetIP:port2scan
	//cewl -d 5 -m 1 -w cewl_out --with-numbers -a --meta_file cewl_metadata_out -e --email_file cewl_emails_out 192.168.1.66:8888
	cewlCmd := exec.Command("bash", "-c", "cewl -d 10 -m 1 -w " + outputPath + "/cewl_out_" + port2scan + " --with-numbers -a --meta_file " + outputPath + "/cewl_metadata_out_" + port2scan + " -e --email_file " + outputPath + "/cewl_emails_out_" + port2scan + " " + targetIP + ":" + port2scan + " && cat " + outputPath + "/cewl_* > gobuster_wordlist && cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt >> gobuster_wordlist")
    	err := cewlCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	//Initiate gobuster on targetIP:port2scan
	//gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /tmp/gobuster_out -u 192.168.1.66:8888 -f -r -k -n
	gobusterCmd := exec.Command("bash", "-c", "gobuster -w " + outputPath + "/gobuster_wordlist_" + port2scan + " -o " + outputPath + "/gobuster_out_" + port2scan + " -u " + targetIP + ":" + port2scan + " -f -r -k -n")
    	err = gobusterCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	//open the file to read
	dirsFilePath := outputPath + "/gobuster_wordlist_" + port2scan
	//dirsFile := OpenFile2Read(dirs)
	dirsFile, _ := os.Open(dirsFilePath)
	defer dirsFile.Close()
	scanner := bufio.NewScanner(dirsFile)
	//Initiate nikto with gobuster's output (Line_by_Line)
	//nikto -h http://192.168.43.4:80/railsgoat
	for scanner.Scan() {
		niktoCmd := exec.Command("bash", "-c", "nikto -h http://" + targetIP + ":" + port2scan + "/" + scanner.Text() + " -Tuning x12567> " + outputPath + "/nikto_scan_out_" + port2scan)
	    	err = niktoCmd.Run()
	    	if err != nil {
			panic(err)
	    	}
	}
	color.White("\n\n[+] Web application vulnerability scan on " + targetIP + ":" + port2scan + " is completed successfully.\n\n")	
}


