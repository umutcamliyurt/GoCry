package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

// List to store decrypted file paths
var decryptedFiles []string

func main() {
	// Get the AES key from user input
	var hexKey string
	fmt.Print("Enter your hex-encoded AES-256 key: ")
	fmt.Scanln(&hexKey)

	// Convert the hex key to bytes
	aesKey, err := hex.DecodeString(hexKey)
	if err != nil || len(aesKey) != 32 {
		fmt.Println("Invalid AES key. It must be a 64-character hex string.")
		return
	}

	// Specify the directory to look for encrypted files (home directory in this case)
	dir := os.Getenv("HOME")

	for {
		// Track if any .enc files were processed in this iteration
		filesProcessed := false

		err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Printf("Error accessing file %s: %v\n", path, err)
				return nil // Continue to next file
			}

			// Skip directories and process only encrypted files with the ".enc" extension
			if info.IsDir() || filepath.Ext(path) != ".enc" {
				return nil
			}

			filesProcessed = true // Mark that we found an encrypted file
			fmt.Println("Decrypting file:", path)

			// Attempt decryption with retries
			for attempts := 0; attempts < 3; attempts++ {
				err := decryptFile(path, aesKey)
				if err == nil {
					break // Exit loop if decryption is successful
				} else {
					fmt.Printf("Attempt %d failed for file %s: %v\n", attempts+1, path, err)
				}
			}

			return nil
		})

		if err != nil {
			fmt.Println("Error walking the path:", err)
		}

		// If no files were processed, exit the loop
		if !filesProcessed {
			break
		}
	}

	// After decryption is complete, create the note.txt file
	err = createNoteFile()
	if err != nil {
		fmt.Println("Error creating note.txt:", err)
	} else {
		fmt.Println("note.txt created successfully.")
	}
}

// decryptFile handles the decryption logic for a single file
func decryptFile(path string, aesKey []byte) error {
	// Read the encrypted file content (which should be Base64-encoded)
	encodedContent, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", path, err)
	}

	// Log the first few bytes of the content to see if it's Base64 encoded
	if len(encodedContent) > 0 {
		fmt.Printf("First few characters of the file: %.20s\n", encodedContent)
	} else {
		return fmt.Errorf("file %s is empty", path)
	}

	// Decode the Base64 encoded content to get the encrypted binary data
	encryptedContent, err := base64.StdEncoding.DecodeString(string(encodedContent))
	if err != nil {
		return fmt.Errorf("failed to decode Base64 content of file %s: %v", path, err)
	}

	// Check that the encrypted content is long enough for decryption
	if len(encryptedContent) < aes.BlockSize {
		return fmt.Errorf("encrypted content too short for file %s", path)
	}

	// Decrypt the file content using AES-256-CBC
	decryptedContent, err := decryptAES256CBC(aesKey, encryptedContent)
	if err != nil {
		return fmt.Errorf("failed to decrypt file %s: %v", path, err)
	}

	// Save the decrypted content back to the original file (overwrites the .enc file)
	originalFilePath := path[:len(path)-4] // Remove the ".enc" extension
	err = ioutil.WriteFile(originalFilePath, decryptedContent, 0644)
	if err != nil {
		return fmt.Errorf("failed to write decrypted file %s: %v", originalFilePath, err)
	}

	// Add the decrypted file to the list for the note
	decryptedFiles = append(decryptedFiles, originalFilePath)

	fmt.Println("File decrypted and saved to:", originalFilePath)

	// Delete the encrypted file
	err = os.Remove(path)
	if err != nil {
		return fmt.Errorf("failed to delete encrypted file %s: %v", path, err)
	}
	fmt.Println("Deleted encrypted file:", path)

	return nil
}


// decryptAES256CBC decrypts data using AES-256-CBC
func decryptAES256CBC(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key length must be 32 bytes for AES-256")
	}

	// Check that the ciphertext is long enough
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract the IV from the beginning of the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Create a new AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create a new CBC mode decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the ciphertext
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	// Unpad the plaintext using PKCS#7 padding
	return unpad(decrypted), nil
}

// unpad removes padding from the decrypted plaintext using PKCS#7
func unpad(data []byte) []byte {
	if len(data) == 0 {
		return data // Return empty data if there's nothing to unpad
	}
	padding := data[len(data)-1]
	if int(padding) > len(data) {
		return data // Return as is if padding is invalid
	}
	return data[:len(data) - int(padding)]
}

// createNoteFile creates a note.txt with details about the decryption process
func createNoteFile() error {
	noteContent := "Decryption Process Complete\n"
	noteContent += "Date: " + time.Now().Format(time.RFC1123) + "\n"
	noteContent += "Decrypted Files:\n"

	for _, filePath := range decryptedFiles {
		noteContent += filePath + "\n"
	}

	noteContent += "\nYour files have been decrypted."

	// Save the note to note.txt
	return ioutil.WriteFile("note.txt", []byte(noteContent), 0644)
}
