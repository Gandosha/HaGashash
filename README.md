# HaGashash
*A concurrent basic script scanner that relies on Nmap, CeWL, Gobuster and Nikto.*

**Tested on:**
- Kali linux x64 2018.4
- go version go1.10.5 linux/amd64

![alt text](https://i.imgflip.com/139g0q.jpg)

**Requirements:**
* Golang - https://golang.org/doc/install
* Nmap - https://nmap.org/download.html
* CeWL - https://digi.ninja/projects/cewl.php
* Gobuster - https://github.com/OJ/gobuster
* Nikto - https://cirt.net/nikto2-docs/installation.html

**Installation:**
* go get github.com/Gandosha/HaGashash
* go get github.com/fatih/color

**Usage:**
* Run with root.
* -host 
--> Scan only this host (Type its IP address or domain name). (default "nil")
* -hosts 
--> Scan only ip addresses that are mentioned in the list (Ex. /root/temp/targets. Path for host list to scan in Line-By-Line form). (default "nil")
* -interface 
--> Name of the interface to use (Required! Run ifconfig before HaGashash in order to choose one). (default "nil")
* -project 
--> Name of the project. (Required! It will create project's folder in /root/HaGashash_Projects/). (default "nil")
* -subnet 
--> Discover alive hosts in your current subnet and scan them.
* -subnets 
--> Discover alive hosts in all subnets and scan them.

**Usage Examples:**
* **(Single host scan)** go run /root/go/src/github.com/Gandosha/HaGashash/main.go -host=192.168.1.1 -interface=enp0s3 -project=example1
* **(Multiple hosts scan from a list)** go run /root/go/src/github.com/Gandosha/HaGashash/main.go -hosts=/root/temp/targets -interface=enp0s3 -project=example2
* **(Scan hosts that are on your current subnet)** go run /root/go/src/github.com/Gandosha/HaGashash/main.go -subnet=true -interface=enp0s3 -project=example3
* **(Scan hosts in all subnets)** go run /root/go/src/github.com/Gandosha/HaGashash/main.go -subnets=true -interface=enp0s3 -project=example3

The tool outputs files in target's directory that can be useful for further enumeration / exploitation.

**My implementation sucks? Feel free to:**
* Not use it.
* Show me how to do it better.
