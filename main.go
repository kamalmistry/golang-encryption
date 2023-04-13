package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func encryptDecryptWithPassword() {
	const password = "hunter2"
	passwordBytes := []byte(password)
	// const password = []byte("hunter2")
	// Encrypt data with password
	armor, err := helper.EncryptMessageWithPassword(passwordBytes, "my message")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("armor: ", armor)

	// Decrypt data with password
	message, err := helper.DecryptMessageWithPassword(passwordBytes, armor)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("message: ", message)
}

func generateKeys(password string) (string, string) {
	// func generateKeys() {
	//const password = "LongSecret"
	passphrase := []byte(password)
	const (
		name  = "Max Mustermann"
		email = "max.mustermann@example.com"
		// password   = "LongSecret"
		// passphrase = []byte(password)
		rsaBits = 2048
	)

	// RSA, string
	privateKey, err := helper.GenerateKey(name, email, passphrase, "rsa", rsaBits)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println("privateKey string: ", privateKey)

	keyRing, err := crypto.NewKeyFromArmoredReader(strings.NewReader(privateKey))
	if err != nil {
		panic(err)
	}
	publicKey, err := keyRing.GetArmoredPublicKey()
	if err != nil {
		panic(err)
	}
	// fmt.Println("publicKey string: ", publicKey)

	return privateKey, publicKey
}

func main() {
	const password = "SomeLongSecret"
	passphrase := []byte(password)
	prikey, pubkey := generateKeys(password)

	message := "this is pretty innocent plain text!!"
	fmt.Println("Original message: ", message)
	// fmt.Println("priKey", prikey)
	// fmt.Println("pubkey", pubkey)

	// encrypt plain text message using public key
	armor, err := helper.EncryptMessageArmored(pubkey, message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("encrypted text: \n", armor)

	// decrypt armored encrypted message using the private key and obtain plain text
	decrypted, err := helper.DecryptMessageArmored(prikey, passphrase, armor)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypted text: \n", decrypted)
}
