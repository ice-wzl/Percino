package main

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"errors"
)

func zzzh() {
	const S = 500000

	for i := 0; i <= S; i++ {
		for j := 2; j <= i/2; j++ {
			if i%j == 0 {
				break
			}
		}
	}
}

func decryptDES3(ciphertext, key, iv []byte) []byte {
	block, _ := des.NewTripleDESCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	decrypted = unpad(decrypted)

	return decrypted
}
func unpad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

func XORRepeat(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("key must not be empty")
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out, nil
}

func DeXORHex(hexCipher, key string) (string, error) {
	cipher, err := hex.DecodeString(hexCipher)
	if err != nil {
		return "", err
	}
	plain, err := XORRepeat(cipher, []byte(key))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
