package cmd

import (
    "fmt"
    "io/ioutil"
    "os"
)

/* This function checks for errors */
func check(e error) {
    if e != nil {
        panic(e)
    }
}

/* This function gets TCP_vuln & UDP_vuln files and creates a summary file. */
func SummaryMaker(projectDirPath string,targetIP string) {
	seperation := "\n\n-----------------------------------------------------------------------------------------------------------------------\n\n"
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
	//Create the summary file and write tcpVulnFileBytes,seperation,udpVulnFileBytes to it.
	sumFile, err2 := os.Create(projectDirPath + "/Summary")
    	check(err2)
    	err = ioutil.WriteFile(projectDirPath + "/Summary", tcpVulnFileBytes, 0644)
    	check(err)
	_, err = sumFile.WriteString(seperation)
    	check(err)
	err = ioutil.WriteFile(projectDirPath + "/Summary", udpVulnFileBytes, 0644)
    	check(err)
	sumFile.Sync()
	fmt.Printf("Summary file for " + targetIP + " is ready.")
	//Delete unnecessary files
	err = os.Remove(projectDirPath + "/TCP_Vulns")
	check(err)
	err = os.Remove(projectDirPath + "/UDP_Vulns")
	check(err)
	err = os.Remove(projectDirPath + "/TCPxml")
	check(err)
	err = os.Remove(projectDirPath + "/UDPxml")
	check(err)
}