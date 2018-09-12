# HaGashash
*A concurrent vulnerability scanner based on Nmap.*

**Installation:**
* go get https://github.com/Gandosha/HaGashash
* go get https://github.com/fatih/color

**Usage:**
* Run with root.
* -host 
--> Scan only this host (Type its IP address or domain name). (default "nil")
* -hosts 
--> Scan only ip addresses that are mentioned in the list (Ex. /root/temp/targets. Path for host list to scan in Line-By-Line form). (default "nil")
* -interface 
--> Name of the interface to use (Required! Run ifconfig before HaGashash in order to choose one). (default "nil")
* -project 
--> Name of the project. (Required! It will create project's folder in /home//HaGashash_Temp/). (default "nil")
* -subnet 
--> Discover alive hosts in your current subnet and scan them.
* -subnets 
--> Discover alive hosts all subnets and scan them.

**Usage Examples:**
* **(Single host scan)** go run main.go -host=192.168.1.1 -interface=enp0s3 -project=example1
* **(Multiple hosts scan from a list)** go run main.go -hosts=/root/temp/targets -interface=enp0s3 -project=example2
* **(Scan hosts that are on your current subnet)** go run main.go -subnet=true -interface=enp0s3 -project=example3
* **(Scan hosts in all subnets)** go run main.go -subnets=true -interface=enp0s3 -project=example3

The tool creates a summary file inside target's directory (Ex. /home/HaGashash_Projects/example_project/192.168.0.1/Summary). 

**My implementation sucks? Feel free to:**
* Not use it.
* Show me how to do it better.
