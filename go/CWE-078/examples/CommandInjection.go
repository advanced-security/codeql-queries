package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
)

func runPing(ip *string) {
	cmdString := fmt.Sprintf("ping %v", *ip)
	fmt.Printf("Command :: %s\n", cmdString)
	cmd := exec.Command(cmdString)
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ip := flag.String("ip", "8.8.8.8", "IP Address to contact")
	flag.Parse()

	log.Printf(" Flag >> %s\n", *ip)
	runPing(ip)

	ip2 := os.Args[0]
	log.Printf(" Argv >> %s", ip2)
	runPing(&ip2)

}
