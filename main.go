package main

import (
	"fmt"
	"os"

	"publickeyhandshake.com/public-key-handshake-assignment/src/handshake"
)

func main() {
	results := handshake.RunAllScenarios()
	allPassed := true

	fmt.Println("public key handshake with CA-based server auth")
	for _, result := range results {
		status := "PASS"
		if !result.Success { status = "FAIL"; allPassed = false }
		fmt.Printf("[%s] %s: %s\n", status, result.Name, result.Details)
	}

	if !allPassed {
		os.Exit(1)
	}
}
