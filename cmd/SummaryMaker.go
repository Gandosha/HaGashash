package cmd

import (
    "io/ioutil"
    "os"
    "github.com/fatih/color"
)

/* This function checks for errors */
func check(e error) {
    if e != nil {
        panic(e)
    }
}

/* This function gets TCP_vuln & UDP_vuln files and creates a summary file. */
func SummaryMaker(projectDirPath string,targetIP string) {
	seperationTCP := "\n\n--------------------------------------------------------------------------------T-C-P--------------------------------------------------------------------------------\n\n"
	seperationUDP := "\n\n--------------------------------------------------------------------------------U-D-P--------------------------------------------------------------------------------\n\n"
	//Open and read TCP_Vulns
	tcpVulnFile, err := os.Open(projectDirPath + "/TCP_Vulns")
	check(err)
	tcpVulnFileBytes, _ := ioutil.ReadAll(tcpVulnFile)
	defer tcpVulnFile.Close()
	//Open and read UDP_Vulns
	udpVulnFile, err1 := os.Open(projectDirPath + "/UDP_Vulns")
	check(err1)
	udpVulnFileBytes, _ := ioutil.ReadAll(udpVulnFile)
	defer udpVulnFile.Close()
	//Create the summary file and write seperationTCP,tcpVulnFileBytes,seperationUDP,udpVulnFileBytes to it.
	sumFile, err := os.OpenFile(projectDirPath + "/Summary", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    	check(err)
    	defer sumFile.Close()
	_, err = sumFile.Write([]byte(seperationTCP))
	check(err)
	_, err = sumFile.Write([]byte(tcpVulnFileBytes))
	check(err)
	_, err = sumFile.Write([]byte(seperationUDP))
	check(err)
	_, err = sumFile.Write([]byte(udpVulnFileBytes))
	check(err)
	sumFile.Sync()
	color.White("\n\n[+] Summary file for " + targetIP + " is ready.\n\n")
}