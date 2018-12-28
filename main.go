package main

import (
	"fmt"
	"time"
	"os"
	"flag"
	"sync"
	"strings"
	"github.com/Gandosha/HaGashash/cmd"
	"github.com/fatih/color"
)

func main() {
	start := time.Now()
	var (
		wg sync.WaitGroup	//Concurrency
		//sliceOfPorts []string	//slice of ports per service
		//service2scan string
	)
	fmt.Println("\n\n\n<-=|HaGashash by Gandosha|=->\n")
	cmd.Init()	
	userEnvVar := os.Getenv("SUDO_USER")
	projectNamePtr := flag.String("project", "nil", "Name of the project. (Required! It will create project's folder in /home" + userEnvVar + "/HaGashash_Projects/).")
	interfacePtr := flag.String("interface", "nil", "Name of the interface to use (Required! Run ifconfig before HaGashash in order to choose one).")
	hostPtr := flag.String("host", "nil", "Scan only this host (Type its IP address or domain name).")
	hostsPtr := flag.String("hosts", "nil", "Scan only ip addresses that are mentioned in the list (Ex. /root/temp/targets. Path for host list to scan in Line-By-Line form).")
	subnetPtr := flag.Bool("subnet", false, "Discover alive hosts in your current subnet and scan them.")
	subnetsPtr := flag.Bool("subnets", false, "Discover alive hosts in all subnets and scan them.")
	flag.Parse()
	switch {
		case *interfacePtr == "nil":
			color.Red("\n\n[!] Please specify an interface name. (Ex. -interface=lo)\n\n")	
			flag.PrintDefaults()
			fmt.Println("\n")
			os.Exit(1)
		case *projectNamePtr == "nil":
			color.Red("\n\n[!] Please specify a name for the project. (Ex. -project=example.com)\n\n")	
			flag.PrintDefaults()
			fmt.Println("\n")
			os.Exit(1)
		case *hostPtr == "nil" && *subnetPtr == false && *subnetsPtr == false && *hostsPtr == "nil":
			color.Red("\n\n[!] Please specify the target. (Ex. -host=example.com or -hosts=/root/temp/targets -subnet=true or -subnets=true)\n\n")	
			flag.PrintDefaults()
			fmt.Println("\n")
			os.Exit(1)
		case *interfacePtr != "nil" && *hostPtr == "nil" && *projectNamePtr != "nil" && *subnetPtr == false && *subnetsPtr == true && *hostsPtr == "nil":
			color.Green("\n\n[!] Starting to scan all subnets.\n\n")
			var targets []string
			ip := cmd.WhatIsMyIP(*interfacePtr)
			tars := cmd.AliveHostsInAllSubnets(targets, ip)
			for i:= range tars {
				path := "/home/" + userEnvVar + "HaGashash_Projects/" + *projectNamePtr + "/" + strings.Trim(tars[i],"'$'\n'")
				cmd.CreateDirIfNotExist(path)	//Create directory for the target
				wg.Add(2)
				go cmd.TCPScan(strings.Trim(tars[i],"'$'\n'"),path,&wg)	//TCP scan
				go cmd.UDPScan(strings.Trim(tars[i],"'$'\n'"),path,&wg)	//UDP scan	
			}
			wg.Wait()	
		case *interfacePtr != "nil" && *hostPtr == "nil" && *projectNamePtr != "nil" && *subnetPtr == true && *subnetsPtr == false && *hostsPtr == "nil":
			color.Green("\n\n[!] Starting to scan your subnet.\n\n")
			var targets []string
			ip := cmd.WhatIsMyIP(*interfacePtr)
			tars := cmd.AliveHostsInSubnet(targets, ip)
			for i:= range tars {
				path := "/home/" + userEnvVar + "HaGashash_Projects/" + *projectNamePtr + "/" + strings.Trim(tars[i],"'$'\n'")
				cmd.CreateDirIfNotExist(path)	//Create directory for the target
				wg.Add(2)
				go cmd.TCPScan(strings.Trim(tars[i],"'$'\n'"),path,&wg)	//TCP scan
				go cmd.UDPScan(strings.Trim(tars[i],"'$'\n'"),path,&wg)	//UDP scan	
			}
			wg.Wait()	
		case *interfacePtr != "nil" && *hostPtr != "nil" && *projectNamePtr != "nil" && *subnetPtr == false && *subnetsPtr == false && *hostsPtr == "nil":
			color.Green("\n\n[!] Starting to perform a single host scan.\n\n")			
			path := "/home/" + userEnvVar + "HaGashash_Projects/" + *projectNamePtr + "/" + strings.Trim(*hostPtr,"'$'\n'")
			cmd.CreateDirIfNotExist(path)	//Create directory for the target
			wg.Add(2)
			go cmd.TCPScan(strings.Trim(*hostPtr,"'$'\n'"),path,&wg)	//TCP scan
			go cmd.UDPScan(strings.Trim(*hostPtr,"'$'\n'"),path,&wg)	//UDP scan
			wg.Wait() 
		case *interfacePtr != "nil" && *hostPtr == "nil" && *projectNamePtr != "nil" && *subnetPtr == false && *subnetsPtr == false && *hostsPtr != "nil":
			color.Green("\n\n[!] Starting to scan targets that are mentioned in " + *hostsPtr + ".\n\n")
			tars := cmd.ReadLine(*hostsPtr)
			for i:= range tars {
				path := "/home/" + userEnvVar + "HaGashash_Projects/" + *projectNamePtr + "/" + strings.Trim(tars[i],"'$'\n'")
				cmd.CreateDirIfNotExist(path)	//Create directory for the target
				wg.Add(2)
				go cmd.TCPScan(strings.Trim(tars[i],"'$'\n'"),path,&wg)	//TCP scan
				go cmd.UDPScan(strings.Trim(tars[i],"'$'\n'"),path,&wg)	//UDP scan	
			}
			wg.Wait()	  			
	}		
	elapsed := time.Since(start)
    	fmt.Println("HaGashash execution time:", elapsed)
		
}
