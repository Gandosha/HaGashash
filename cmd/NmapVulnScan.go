package cmd

import (
 	"os/exec"
	"bufio"
	"sync"
	"os"
	"github.com/fatih/color"
)


/* This function performs a nmap TCP script scan on target IP. */
func NmapTCPScan(targetIP string, xmlPath string, workgroup *sync.WaitGroup) {
	color.Green("\n\n[!] Starting to scan " + targetIP + " for TCP interesting stuff.\n\n")
	nmapCmd := exec.Command("bash", "-c", "nmap -sS -p- -A -T4 -Pn -vv -oX " + xmlPath + "/Nmap_TCP_scan_output " + targetIP)
    	err := nmapCmd.Run()
    	if err != nil {
        	panic(err)
    	}
	color.White("\n\n[+] Nmap's TCP script scanning on " + targetIP + " is completed successfully.\n\n")
	workgroup.Done()
}

/* This function performs a nmap UDP script scan on target IP. */
func NmapUDPScan(targetIP string, xmlPath string, workgroup *sync.WaitGroup) {
	color.Green("\n\n[!] Starting to scan " + targetIP + " for UDP interesting stuff.\n\n")
	nmapCmd := exec.Command("bash", "-c", "nmap -sU -p- -A -T4 -Pn -vv -oX " + xmlPath + "/Nmap_UDP_scan_output " + targetIP)
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

