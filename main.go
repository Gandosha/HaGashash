package main

import (
	"fmt"
	"os"
	"flag"
	"strings"
	"io/ioutil"
	"Hagashash/cmd"
	"github.com/fatih/structs"
)


func main() {	
	userEnvVar := os.Getenv("SUDO_USER")
	projectNamePtr := flag.String("project", "nil", "Name of the project. (Required! It will create project's folder in /home/" + userEnvVar + "/HaGashash_Temp/).")
	interfacePtr := flag.String("interface", "nil", "Name of the interface to use (Required! Run ifconfig before HaGashash in order to choose one).")
	//var myIpAddress string = whatIsMyIP(*interfacePtr) 
	//fmt.Println(myIpAddress)
	//hostPtr := flag.String("host", "nil", "Skip host discovery. Scan only this host (Type its IP address or domain name).")
	//subnetPtr := flag.Bool("subnet", true, "Discover alive hosts in subnet and scan them.")
	/*dnsPtr := flag.Bool("dns", false, "Locate non-contiguous IP space and hostnames against specified domain. (Type "true" or "false").")
	nmap spoof
	nmap decoy*/
	flag.Parse()
	//v := Targets{}	
	//whatIsMyIP(*interfacePtr)
	//fmt.Println(interfacePtr)
	//targetsMap := make(map[int]string)	//use this as an argument in scanTargetsInSubnet(targetsMap)
	switch {
	case *interfacePtr == "nil":
		fmt.Println("\n[!] Please specify an interface name. (Ex. -interface=lo)\n\n")	
		flag.PrintDefaults()
		fmt.Println("\n")
		os.Exit(1)
	case *projectNamePtr == "nil":
		fmt.Println("\n[!] Please specify a name for the project. (Ex. -project=example.com)\n\n")	
		flag.PrintDefaults()
		fmt.Println("\n")
		os.Exit(1)
	/*case *hostPtr == "nil":
		//start to scan subnet
		fmt.Println("\n[!] Starting to scan your subnet (/24).\n\n")
		//whatIsMyIP(*interfacePtr)
		scanTargetsInSubnet(myIpAddress)
	/*case *dnsPtr == true:
		//start fierce */
	default:
		//start to scan subnet
		fmt.Println("\n[!] Starting to scan your subnet.\n")
		var targets []string
		ip := cmd.WhatIsMyIP(*interfacePtr)
		tars := cmd.AliveHostsInSubnet(targets, ip)
		for i:= range tars {
			path := "/home/" + userEnvVar + "HaGashash_Projects/" + *projectNamePtr + "/" + strings.Trim(tars[i],"'$'\n'")
			cmd.CreateDirIfNotExist(path)
			cmd.NmapTCPScan(strings.Trim(tars[i],"'$'\n'"),path)	//TCP scan
			//Parse TCPxml
			xmlFile, err := os.Open(path + "/TCPxml")
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("[!] Successfully opened: " + path + "/TCPxml.\n")
			bytes, _ := ioutil.ReadAll(xmlFile)
			defer xmlFile.Close()
			parsed, err := cmd.Parse(bytes)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("[!] Successfully parsed: " + path + "/TCPxml.\n")
			scanResultsMap := structs.Map(parsed)
			for index := range scanResultsMap {
				if index == "Hosts" {
					fmt.Println("scanResultsMap[index]: ",scanResultsMap[index])
				}
			}	
   			//cmd.ExtractPorts(parsed, "TCP")
			//Write parsed var to file and extract ports using function in NmapXMLparser.go							  			
		} 
	}
		
}