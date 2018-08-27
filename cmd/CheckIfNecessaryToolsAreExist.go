package cmd

import (
	"fmt"
 	"os/exec"
)

/* This function checks if all tools that are necessary for running properly, exist in system.
The function gets a slice of necessary tools and print if they exist or not. */
func CheckIfNecessaryToolsAreExist(command string) {
    path, err := exec.LookPath(command)
    if err != nil {
        fmt.Printf("didn't find " + command + " executable\n")
    } else {
        fmt.Printf(command + " executable is in '%s'\n", path)
    }
}

/* Initiate */
func Init() {
	tools := []string{"nmap", "fierce", ""}
	for i := range tools {
		CheckIfNecessaryToolsAreExist(tools[i])
	}


}