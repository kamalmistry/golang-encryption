package main

import (
	"fmt"
	"log"

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

	// Curve25519, string
	// ecKey, err := helper.GenerateKey(name, email, passphrase, "x25519", 0)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println("ecKey: ", ecKey)

	// RSA, Key struct
	rsaKeyS, err := crypto.GenerateKey(name, email, "rsa", rsaBits)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println("rsaKey struct: ", rsaKeyS.GetEntity().PrivateKey)
	pubKey, err := rsaKeyS.GetArmoredPublicKey()
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println("pubKey: ", pubKey)

	return privateKey, pubKey
	// Curve25519, Key struct
	// ecKeyS, err := crypto.GenerateKey(name, email, "x25519", 0)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println("ecKeyS: ", ecKeyS)
}
func main() {
	fmt.Println("Hi start now ...")
	const password = "LongSecret"
	passphrase := []byte(password)
	prikey, pubkey := generateKeys(password)

	fmt.Println("priKey", prikey)
	fmt.Println("pubkey", pubkey)

	// encrypt plain text message using public key
	armor, err := helper.EncryptMessageArmored(pubkey, "this is pretty innocent plain text!!")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("armor: ", armor)

	// decrypt armored encrypted message using the private key and obtain plain text
	decrypted, err := helper.DecryptMessageArmored(prikey, passphrase, armor)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypted: ", decrypted)
}
