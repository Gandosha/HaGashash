package cmd

import (
	"os"
	"log"
	"fmt"
	"io/ioutil"
	"strings"
	"os/exec"
	"github.com/fatih/color"
)

/* This function extracts attacker's IP address from ifconfig command output according to the interface that is given as a flag. */
func WhatIsMyIP(netInterface string) string{
	ifconfigCmd := exec.Command("ifconfig")
	ifconfigIn, _ := ifconfigCmd.StdinPipe()
	ifconfigOut, _ := ifconfigCmd.StdoutPipe()
	ifconfigCmd.Start()
	ifconfigIn.Write([]byte("ifconfig"))
	ifconfigIn.Close()
	ifconfigBytes, _ := ioutil.ReadAll(ifconfigOut)
	ifconfigCmd.Wait()
	ifconfig := string(ifconfigBytes)
	netInterfaceIndex := strings.Index(ifconfig, netInterface)
	ifconfigTrimmed := ifconfig[netInterfaceIndex:netInterfaceIndex+250]
	inetIndex := strings.Index(ifconfigTrimmed, "inet")
	ifconfigTrimmed2 := ifconfigTrimmed[inetIndex+5:]
	spaceIndex := strings.Index(ifconfigTrimmed2, " ")
	ipAddress := ifconfigTrimmed2[:spaceIndex]	
	return ipAddress
}

/* This function creates a directory if it does not exist. Otherwise do nothing. */
func CreateDirIfNotExist(dir string) {
	nmapCmd := exec.Command("bash", "-c", "sudo mkdir -p " + dir)
    	err := nmapCmd.Start()
    	if err != nil {
        	panic(err)
    	}
	err = nmapCmd.Wait()	
	if err != nil {
        	panic(err)
    	}
	color.White("\n[+] Directory created at: " + dir + ".")
}

/* This function checks if all tools that are necessary for running properly, exist in system.
The function gets a slice of necessary tools and print if they exist or not. */
func CheckIfNecessaryToolsAreExist(command string) {
    path, err := exec.LookPath(command)
    if err != nil {
        color.Red("\n[!] didn't find " + command + " executable! Please install it and then run HaGashash again.\n")
    } else {
        color.Cyan("[+] " + command + " executable is in '%s'\n", path)
    }
}

/* Initiate */
func Init() {
	tools := []string{"nmap", "ifconfig","nikto"}
	for i := range tools {
		CheckIfNecessaryToolsAreExist(tools[i])
	}
	color.White("[!] Dependencies check is completed successfully.")
}

//This function opens a file for reading
func OpenFile2Read(outputPath string) string {
	file, err := os.Open(outputPath + "/nmap_tcp_scan_output_grepable")
	if err != nil {
		log.Fatal(err)
	}
	grepable, err := ioutil.ReadAll(file)
    	if err != nil {
        	log.Fatal(err)
    	}
	return string(grepable)
}

/*This function takes a nmap_tcp_scan_output_grepable file with a service name.
The function returns a port number of the service name that was specified.*/
func PortExtractor(data string, serviceName string) (bool, string, string) {
	var (		
		portsWord = "Ports:"
		space = " "
		spaceIndex int 
		spaceIndexes []int
		backSlash = "/"
		backSlashIndex int
		backSlashIndexes []int
		comma = ","
		commaIndex int
		commaIndexes []int
		serviceNameIndex int
	)
	portsWordIndex := strings.Index(data, portsWord)
	if ( portsWordIndex != -1 ) {
		data = data[portsWordIndex+6:]
	}
	fmt.Println("\n\nLength:\n",len(data))
	fmt.Println("\n\ndata_1\n",data)
	//Space,comma and backSlash mapper
	for s1, v1 := range data {
		switch {
			case string(v1) == space:
				spaceIndexes = append(spaceIndexes,s1)
			case string(v1) == backSlash:
				backSlashIndexes = append(backSlashIndexes,s1)
			case string(v1) == comma:
				commaIndexes = append(commaIndexes,s1)
		}	
	}
	fmt.Println("\n\nspaceIndexes\n",spaceIndexes)
	fmt.Println("\n\nbackSlashIndexes\n",backSlashIndexes)
	fmt.Println("\n\ncommaIndexes\n",commaIndexes)
	serviceNameIndex = strings.Index(data, serviceName)	//Find service's name index
	//spaceIndex extractor
	for s2, v2 := range spaceIndexes {
		if ( v2 > serviceNameIndex ) {
			spaceIndex = spaceIndexes[s2-1]
			break
		}	
	}
	//backSlashIndex extractor
	for s3, v3 := range backSlashIndexes {
		if ( v3 < serviceNameIndex && v3 > spaceIndex ) {
			backSlashIndex = backSlashIndexes[s3]
			break
		}	
	}
	//commaIndex extractor
	for s4, v4 := range commaIndexes {
		if ( v4 > serviceNameIndex ) {
			commaIndex = commaIndexes[s4]
			break
		}	
	}
	fmt.Println("\n\nserviceNameIndex\n",serviceNameIndex)
	fmt.Println("\n\nspaceIndex\n",spaceIndex)
	fmt.Println("\n\nbackSlashIndex\n",backSlashIndex)
	fmt.Println("\n\ncommaIndex\n",commaIndex)
	portNumber := data[spaceIndex+1:backSlashIndex]
	fmt.Println("\n\nportNumber extracted:\n",portNumber)
	data = data[commaIndex:]
	serviceNameIndex = strings.Index(data, serviceName)	//Find service's name index
	fmt.Println("\n\nLength:\n",len(data))
	fmt.Println("\n\ndata_after_cut:\n",data)	
	if ( serviceNameIndex == -1 || len(commaIndexes) == 1) {
		return false, portNumber, "nil"	//No more serviceName entries
	}	
	if ( len(data) > 0 && serviceNameIndex != -1 ) {
		return true, portNumber, data	//There are more entries for that serviceName
	}	
	return false,"nil","nil"
}