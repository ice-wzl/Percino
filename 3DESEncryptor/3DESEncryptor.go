package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	shellcodeFile := flag.String("f", "", "File containing your shellcode")
	flag.Parse()

	if *shellcodeFile == "" {
		fmt.Printf("[-] Please include your raw shellcode file with -f\n")
		os.Exit(1)
	}

	programDriver(*shellcodeFile)
}

func programDriver(shellcodeFile string) {
	shellcode, err := getShellcode(shellcodeFile)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
	}

	key := generateRandomBytes(24)
	iv := generateRandomBytes(des.BlockSize)

	fmt.Printf("Key: %s\n", formatShellcode(key))
	fmt.Printf("IV: %s\n", formatShellcode(iv))

	encryptedShellcode, err := encryptDES3(shellcode, key, iv)
	if err != nil {
		fmt.Println("Error 3DES:", err)
		return
	}

	fmt.Printf("Shellcode encrypted: %s\n", formatShellcode(encryptedShellcode))

	writeShellcode([]byte(formatShellcode(encryptedShellcode)))
}

func getShellcode(shellCodeFile string) ([]byte, error) {
	f, err := os.Open(shellCodeFile)
	if err != nil {
		return nil, fmt.Errorf("[-] Error opening: %v: %v", shellCodeFile, err)
	}
	defer f.Close()
	shellcodeBytes, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("[-] Error reading: %v: %v", shellCodeFile, err)
	}
	return shellcodeBytes, nil
}

func writeShellcode(finalShellcode []byte) {
	err := os.WriteFile("final_shellcode.txt", finalShellcode, 0o644)
	if err != nil {
		fmt.Printf("[-] Error writing shellcode to: final_shellcode.txt\n")
	}
}

func generateRandomBytes(size int) []byte {
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random bytes: %v", err))
	}
	return randomBytes
}

func encryptDES3(plaintext, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(plaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func formatShellcode(data []byte) string {
	output := ""
	for _, b := range data {
		output += fmt.Sprintf("\\x%02x", b)
	}
	return output
}
