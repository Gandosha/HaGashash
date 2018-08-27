package cmd

import (
	"fmt"
 	"os/exec"
)


/* This function performs a nmap TCP/UDP/vulnerability scan on target IP. */
func NmapVulnScan(targetIP string, xmlPath string) {
	fmt.Println("\n\n[!] Starting to scan " + targetIP + " for TCP ports.")
	nmapCmd := exec.Command("bash", "-c", "sudo nmap -sS -p- -T4 -Pn -vv -oX " + xmlPath + "/TCPxml " + targetIP)
    	err := nmapCmd.Start()
    	if err != nil {
        	panic(err)
    	}
	err = nmapCmd.Wait()	
	if err != nil {
        	panic(err)
    	}
	/*call xmlParser
	parseXML(xmlPath + "/TCPxml")*/
	//Vuln scan those ports
	/* fmt.Println("\n\n[!] Starting to scan " + targetIP + " for UDP ports.")
	nmapCmd = exec.Command("bash", "-c", "sudo nmap -sU -p- -T4 -Pn -vv -oX " + xmlPath + "/UDPxml " + targetIP)
    	err = nmapCmd.Start()
    	if err != nil {
        	panic(err)
    	}
	err = nmapCmd.Wait()	
	if err != nil {
        	panic(err)
    	}
    	fmt.Println("\n") */
}