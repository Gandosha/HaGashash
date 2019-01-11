package cmd

import (
	"fmt"
 	"strings"
 	"os/exec"
	"bufio"
	"sync"
	"github.com/fatih/color"
	"os"
	"crypto/tls"
	"net/http"
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

/* This function perfoms a HTTP check against the target.
The function gets an IP address and a port number. It returns true if the target is reachable via HTTP or false if not.*/
func HttpCheck(targetIP string, port2scan string) bool {
	_, err := http.Get("http://" + targetIP + ":" + port2scan + "/")
	if err != nil {
		return false
	}
	return true
} 

/* This function perfoms a HTTPS check against the target.
The function gets an IP address and a port number. It returns true if the target is reachable via HTTPS or false if not (security check is disabled).*/
func HttpsCheck(targetIP string, port2scan string) bool {
	tr := &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	_, err := client.Get("https://" + targetIP + ":" + port2scan + "/")
	if err != nil {
		return false
	}
	return true
}

/* This function performs a nmap TCP script scan on target IP.
It initiates PortExtractor and WebScan function against the target. */
func TCPScan(targetIP string, outputPath string, workgroup *sync.WaitGroup) {
	var (
		sliceOfPorts []string	//slice of ports per service
		service2export string
		serviceNameIndex int
		isHTTP bool	//HttpCheck function returned value
		isHTTPS bool	//HttpsCheck function returned value
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
		answer, portnum, dat, commaIndex := PortExtractor(grepable, service2export)
		sliceOfPorts = append(sliceOfPorts,portnum)
		for ( answer && commaIndex != 0 ) {
			answer, portnum, dat, commaIndex = PortExtractor(dat,service2export)
			sliceOfPorts = append(sliceOfPorts,portnum)
		}
		fmt.Println("\n\n[!] Web application ports to be scanned on " + targetIP + " are:")
		fmt.Println(sliceOfPorts)
		//WebScan on extracted ports
		for _, port := range sliceOfPorts {
			isHTTPS = HttpsCheck(targetIP, port)
			isHTTP = HttpCheck(targetIP, port)
			switch {
				case isHTTPS == true && isHTTP == true:
					go WebScan("https",targetIP, outputPath, port)
					go WebScan("http",targetIP, outputPath, port)
				case isHTTPS == false && isHTTP == true:
					go WebScan("http",targetIP, outputPath, port)
				case isHTTPS == true  && isHTTP == false:
					go WebScan("https",targetIP, outputPath, port)
				case isHTTPS == false  && isHTTP == false:
					break	
			}
			
		}
	}
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

/* This function performs a web application vulnerability scan against a target (protocol://IP:port/directory). */
func WebScan(protocol string, targetIP string, outputPath string, port2scan string) {
	color.Green("\n\n[!] Starting to scan " + targetIP + ":" + port2scan + " for web application vulnerabilities.\n\n")
	//Initiate cewl
	color.Green("\n\n[!] CeWL initiated on: " + protocol + "://" + targetIP + ":" + port2scan + ".\n\n")
	cewlCmd := exec.Command("bash", "-c", "cewl -m 1 -w " + outputPath + "/cewl_out_" + port2scan + "_" + protocol + " --with-numbers -a --meta_file " + outputPath + "/cewl_metadata_out_" + port2scan + "_" + protocol + " -e --email_file " + outputPath + "/cewl_emails_out_" + port2scan + "_" + protocol + " " + protocol + "://" + targetIP + ":" + port2scan + " && cat " + outputPath + "/cewl_* >> " + outputPath + "/gobuster_wordlist_" + protocol + "_" + port2scan + " && cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt >> " + outputPath + "/gobuster_wordlist_" + protocol + "_" + port2scan)
    	err := cewlCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	//Initiate gobuster using cewl's output and /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
	color.Green("\n\n[!] Gobuster initiated on: " + protocol + "://" + targetIP + ":" + port2scan + ".\n\n")
	gobusterCmd := exec.Command("bash", "-c", "gobuster -w " + outputPath + "/gobuster_wordlist_" + protocol + "_" + port2scan + " -o " + outputPath + "/gobuster_out_" + port2scan + "_" + protocol + " -u " + protocol + "://" + targetIP + ":" + port2scan + " -f -r -k -n")
    	err = gobusterCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	/*Measure the size of "/gobuster_out_" + port2scan + "_" + protocol. If it's 0 bytes, just do nikto -h [Target_IP]:[Port]
	Stat returns file info. It will return an error if there is no file. */
	var fileInfo os.FileInfo
	fileInfo, err = os.Stat(outputPath + "/gobuster_out_" + port2scan + "_" + protocol)
	if err != nil {
		panic(err)
	}
	switch {
		case fileInfo.Size() == 0:
			color.Green("\n\n[!] Nikto initiated on: " + protocol + "://" + targetIP + ":" + port2scan + ".\n\n")
			niktoCmd := exec.Command("bash", "-c", "nikto -h " + protocol + "://" + targetIP + ":" + port2scan + " -Tuning x12567 >> " + outputPath + "/nikto_scan_out_" + port2scan + "_" + protocol)
			err = niktoCmd.Run()
		    	if err != nil {
				panic(err)
		    	}
		case fileInfo.Size() > 0:
			//Open gobuster's output file to read
			dirsFilePath := outputPath + "/gobuster_out_" + port2scan + "_" + protocol
			dirsFile, _ := os.Open(dirsFilePath)
			defer dirsFile.Close()
			scanner := bufio.NewScanner(dirsFile)
			//Initiate nikto with gobuster's output (Line_by_Line)
			for scanner.Scan() {
				color.Green("\n\n[!] Nikto initiated on: " + protocol + "://" + targetIP + ":" + port2scan + scanner.Text() + ".\n\n")
				niktoCmd := exec.Command("bash", "-c", "echo -e '\n\n" + protocol + "://" + targetIP + ":" + port2scan + scanner.Text() + "\n\n' >> " + outputPath + "/nikto_scan_out_" + port2scan + " && nikto -h " + protocol + "://" + targetIP + ":" + port2scan + scanner.Text() + " -Tuning x12567 >> " + outputPath + "/nikto_scan_out_" + port2scan + "_" + protocol)
			    	err = niktoCmd.Run()
			    	if err != nil {
					panic(err)
			    	}
			}
	}
	color.White("\n\n[+] Web application vulnerability scanning on " + protocol + "://" + targetIP + ":" + port2scan + " is completed successfully.\n\n")	
}


