package main

import (
	"os"
	"os/exec"
)

func example1() {
	subCmd := os.Args[1]
	cmd := exec.Command(subCmd)
	cmd.Run()
}
