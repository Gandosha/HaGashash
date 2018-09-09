package cmd

import (
	"os/exec"
	"github.com/fatih/color"
)


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
	color.Cyan("[!] Directory created at: " + dir + ".")



}
      