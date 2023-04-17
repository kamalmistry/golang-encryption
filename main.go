package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// Encrypt message only using password
func encryptDecryptWithPasswordOnly(password string) {
	// const password = "hunter2"
	passwordBytes := []byte(password)
	// const password = []byte("hunter2")
	// Encrypt data with password
	armor, err := helper.EncryptMessageWithPassword(passwordBytes, "my secret message..")
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

// Generate RSA private and public keys using the passphrase
// It also generate keys files in current directory with names:
// "private_key.asc" and "public_key.asc"
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

	// Key files path
	privateKeyFilePath := ".\\private_key.asc"
	publicKeyFilePath := ".\\public_key.asc"

	// RSA, string
	privateKey, err := helper.GenerateKey(name, email, passphrase, "rsa", rsaBits)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println("privateKey string: ", privateKey)

	fmt.Println("Writing private key to file: ", privateKeyFilePath)
	err = ioutil.WriteFile(privateKeyFilePath, []byte(privateKey), 0644)
	if err != nil {
		fmt.Println("Error writing private key to file:", err)
		panic(err)
	}

	keyRing, err := crypto.NewKeyFromArmoredReader(strings.NewReader(privateKey))
	if err != nil {
		panic(err)
	}
	publicKey, err := keyRing.GetArmoredPublicKey()
	if err != nil {
		panic(err)
	}
	// fmt.Println("publicKey string: ", publicKey)

	fmt.Println("Writing public key to file: ", publicKeyFilePath)
	err = ioutil.WriteFile(publicKeyFilePath, []byte(publicKey), 0644)
	if err != nil {
		fmt.Println("Error writing public key to file:", err)
		panic(err)
	}

	return privateKey, publicKey
}

func main() {
	const password = "SomeLongSecret"

	// encryptDecryptWithPasswordOnly(password)

	passphrase := []byte(password)
	prikey, pubkey := generateKeys(password)

	fmt.Println("priKey: \n", prikey)
	fmt.Println("pubkey: \n", pubkey)

	// encryptDecryptUsingKeyStrings(pubkey, prikey, passphrase)

	encryptDecryptFileUsingKeyStrings(pubkey, prikey, passphrase, ".\\originalData.csv")

	// publicKeyFilePath := ".\\public_key.asc"
	// privateKeyFilePath := ".\\private_key.asc"
	// encryptDecryptUsingKeyFiles(publicKeyFilePath, privateKeyFilePath, passphrase)
}

func encryptDecryptUsingKeyFiles(publicKeyFilePath string, privateKeyFilePath string, passphrase []byte) {

	// Load the public key from a file
	fmt.Println("Loading the public key from a file ..")
	pubkey, err := ioutil.ReadFile(publicKeyFilePath)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Load the private key from a file
	fmt.Println("Loading the private key from a file ..")
	prikey, err := ioutil.ReadFile(privateKeyFilePath)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	message := "this is pretty innocent plain text message !!"
	fmt.Println("Original message: ", message)

	// encrypt plain text message using public key
	armor, err := helper.EncryptMessageArmored(string(pubkey), message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("encrypted message: \n", armor)

	// decrypt armored encrypted message using the private key and obtain plain text
	decrypted, err := helper.DecryptMessageArmored(string(prikey), passphrase, armor)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypted message: \n", decrypted)
}

func encryptDecryptUsingKeyStrings(pubkey string, prikey string, passphrase []byte) {
	message := "this is pretty innocent plain text!!"
	fmt.Println("Original message: ", message)

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

func encryptDecryptFileUsingKeyStrings(pubkey string, prikey string, passphrase []byte, csvFilePath string) {

	fileData := getFileDataAsString(csvFilePath)
	fmt.Println("Original file data: ", fileData)

	// encrypt file data message using public key
	armor, err := helper.EncryptMessageArmored(pubkey, fileData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("encrypted text: \n", armor)

	// write the encrypted text into the file.
	localEncryptedFilePath := ".\\encryptedFile.csv"
	fmt.Println("Writing encrypted data to a file: ", localEncryptedFilePath)
	err = os.WriteFile(localEncryptedFilePath, []byte(armor), 0644)
	if err != nil {
		fmt.Println("Error writing encrypted data to file:", err)
		panic(err)
	}

	// Read the data from an encrypted file
	fmt.Println("Loading the encrypted data from a file ..")
	encData := getFileDataAsString(localEncryptedFilePath)

	decrypted, err := helper.DecryptMessageArmored(prikey, passphrase, encData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypted csv data: ")
	fmt.Println(decrypted)
}

func getIoReaderFromString(data string) io.Reader {
	return strings.NewReader(data)
}

func getFileDataAsString(filePath string) string {
	// Read the whole file
	b, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	// Convert the bytes to a string and returns
	return string(b)
}
