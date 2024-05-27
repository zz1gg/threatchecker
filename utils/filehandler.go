package utils

import (
	"encoding/hex"
	"fmt"
	"github.com/gabriel-vasile/mimetype"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

type FileType int

func DownloadFile(fileurl string) ([]byte, error) {

	resp, err := http.Get(fileurl)
	if err != nil {
		fmt.Println("[-] Error Downloading file:%v\n", err)
		return nil, err
	}

	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)

	if err != nil {
		fmt.Println("[-] Error Reading file:%v\n", err)
		return nil, err
	}
	return content, nil
}

// Check absolute path of the specified file,
// Add absolute path of the specified file
func CheckFileAbs(fileName string) string {
	var absFileName string

	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("[-] Error getting current directory:", err)
		return ""
	}
	//fmt.Println("Current directory:", currentDir)

	_, err = os.Executable()
	if err != nil {
		fmt.Println("[-] Error getting absolute path of the running program:", err)
		return ""
	}
	//fmt.Println("Absolute path of the running program:", absolutePath)
	/*

		if !filepath.IsAbs(fileName) {
			//fmt.Println("[-] The specified file has an absolute path.")
			fmt.Println("[-] The specified file does not have an absolute path.")
		}

	*/

	//
	absFileName, err = filepath.Abs(fileName)
	if err != nil {
		fmt.Println("[-] Error getting absolute path of the specified file:", err)
		return ""
	}

	//
	if !filepath.IsAbs(fileName) || filepath.Dir(absFileName) == currentDir {
		absFileName = filepath.Join(currentDir, filepath.Base(fileName))
	}

	//fmt.Println("[+] Absolute path of the specified file:", absFileName)

	return absFileName
}

// Splits the original array and hex dump bad bytes
func HalfSplitter(originalArray []byte, lastGood int) []byte {
	splitSize := (len(originalArray)-lastGood)/2 + lastGood
	splitArray := make([]byte, splitSize)

	if len(originalArray) == splitSize+1 {
		msg := red.Sprintf("[!] Identified end of bad bytes at offset 0x%X", len(originalArray))
		fmt.Println(msg)

		offendingSize := min(len(originalArray), 256)
		offendingBytes := make([]byte, offendingSize)
		copy(offendingBytes, originalArray[len(originalArray)-offendingSize:])

		fmt.Println(hex.Dump(offendingBytes))
		Complete = true
	}

	copy(splitArray, originalArray[:splitSize])
	return splitArray
}

// Overshot increases the size of the split array
func Overshot(originalArray []byte, splitArraySize int) []byte {
	newSize := (len(originalArray)-splitArraySize)/2 + splitArraySize

	if newSize == len(originalArray)-1 {
		Complete = true

		if Malicious {
			_, err := yellow.Println("[!] File is malicious, but couldn't identify bad bytes")
			if err != nil {
				return nil
			}
		}
	}

	newArray := make([]byte, newSize)
	copy(newArray, originalArray[:newSize])
	return newArray
}

// Find the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Print hex dump of the byte array
func Hexdump(data []byte, offset, length uint) string {

	startIndex := int(offset)
	endIndex := int(offset + length)
	featureData := data[startIndex:endIndex]
	dump := hex.Dump(featureData)
	//fmt.Printf("%s", dump)
	return dump
}

const (
	Unknown FileType = iota
	Bin
	Script
)

func IsBinary(fileBytes []byte) FileType {

	detectedMIME := mimetype.Detect(fileBytes)

	//isBinary := true
	for mtype := detectedMIME; mtype != nil; mtype = mtype.Parent() {
		if mtype.Is("text/plain") {
			//isBinary = false
			return Script
		}
	}

	//fmt.Println(isBinary, detectedMIME)
	return Bin
}
