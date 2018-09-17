package cmd

import (
	"github.com/fatih/color"
 	"os/exec"
)

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
	tools := []string{"nmap", "ifconfig"}
	for i := range tools {
		CheckIfNecessaryToolsAreExist(tools[i])
	}
	color.White("[!] Dependencies check is completed successfully.")
}