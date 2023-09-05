package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	key := byte(0x9A)

	if len(os.Args) < 2 {
		fmt.Println("Usage: encrypt <path>")
		os.Exit(1)
	}

	// Get the path from the command line argument
	path := os.Args[1]

	_, err := os.Stat(path)
	if err != nil {
		log.Fatalf("[FATAL] File %s doesn't exist", path)
	}
	fmt.Println("[+] Reading bytes of shellcode")
	// Read the entire file into a byte slice
	fileData, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[FATAL] Error reading file:", err)
	}

	encryptedData := make([]byte, len(fileData))
	fmt.Println("[+] Encrypting bytes of shellcode")

	for i := 0; i < len(encryptedData); i++ {
		encryptedData[i] = fileData[i] ^ key
	}
	fmt.Printf("[+] Writing encoded bytes at %s", path+"_ENC")

	os.WriteFile(path+"_ENC", encryptedData, 0644)
}
