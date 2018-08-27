package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"flag"
	"strings"
	"Hagashash/cmd"
	
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
		var t Targets
		ip := cmd.WhatIsMyIP(*interfacePtr)
		tars := cmd.AliveHostsInSubnet(targets, ip)
		for i:= range tars {
			path := "/home/" + userEnvVar + "/HaGashash_Projects/" + *projectNamePtr + "/" + strings.Trim(tars[i],"'$'\n'")
			cmd.CreateDirIfNotExist(path)
			cmd.NmapVulnScan(strings.Trim(tars[i],"'$'\n'"),path)
			//Parse TCPxml
			xmlFile, err := os.Open(path + "/TCPxml")
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("Successfully Opened " + path + "/TCPxml")
			defer xmlFile.Close()
			xmldecoderOut, err := XmlDecoder(xmlFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			    }	
			//Parse UDPxml
			xmlFile, err = os.Open(path + "/UDPxml")
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("Successfully Opened " + path + "/UDPxml")
			defer xmlFile.Close()
			xmldecoderOut, err = XmlDecoder(xmlFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			    }			
			fmt.Println(xmldecoderOut)					  			
		}
		output, err := xml.MarshalIndent(t, "  ", "    ")
		if err != nil {
			fmt.Printf("error: %v\n", err)
		}
		os.Stdout.Write(output)
		/*fmt.Println(t.Address)
		fmt.Println(t.Port)	
		fmt.Println(t)
		for j := 0; j < len(t.Targets); j++ {
			fmt.Println("Address: " + t.Targets[j].Address)
			fmt.Println("Port: " + t.Targets[j].Port)
		} */
		
		//export to html
}
		
}