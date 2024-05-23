package utils

import (
	"fmt"
	"os"
	"strings"
)

var filecontents []byte
var err error

// Check InFile is url-file or disk-file,return file contents bytes
func CheckInFile(targeturl, targetfile string) []byte {

	if targeturl == "" && targetfile == "" {

		fmt.Println("[-] File or URL required!")
		os.Exit(1)
	} else if targeturl != "" {
		//Downloading File
		fmt.Println("[+] Downloading URL File!")

		filecontents, err = DownloadFile(targeturl)
		fmt.Printf("[+] Target file size is : %d bytes \n", len(filecontents))
		if err != nil {
			fmt.Println("[-] Failed to download file: ", err)
			os.Exit(1)
		}

		fmt.Println("[+] Reading URL File to bytes!")

		return filecontents

	} else if targetfile != "" {
		//Read Disk Target File Bytes
		fmt.Println("[+] Reading Disk File to bytes...")
		//Analyze Disk Target File
		//CheckFileType(targetfile)

		filecontents, err = os.ReadFile(targetfile)
		fmt.Printf("[+] Target file size is : %d bytes \n", len(filecontents))
		if err != nil {
			fmt.Println("[-] Error Reading Disk file: ", err)
			os.Exit(1)
		}

		return filecontents
	}

	return nil
}

// Check filetype, Check Engine
func CheckEngine(engine, filetype string, filecontents []byte) {

	targetengine := strings.ToLower(engine)

	if filetype == "" {
		fmt.Println("[+] No specified filetype")
		switch targetengine {

		case "defender":
			fmt.Println("[+] Start Checking with Defender")
			defender := NewDefender(filecontents)
			defender.AnalyzeFile()
		case "amsi":
			fmt.Println("[+] Start Checking with AMSI")
			amsi := NewAMSIInstance("")
			amsi.AnalyzeBytes(filecontents, "TestBuffer")
		case "":
			fmt.Println("[+] Start Checking with AMSI")
			amsi := NewAMSIInstance("")
			amsi.AnalyzeBytes(filecontents, "TestBuffer")
		default:

			fmt.Println("[-] Input right Engine (AMSI or Defender)?")
			os.Exit(1)

		}
	} else {
		switch IsBinary(filecontents) {

		case 1: //Bin
			fmt.Println("[+] Filetype is Bin")
			if targetengine == "defender" {
				fmt.Println("[+] Start Checking with Defender")
				defender := NewDefender(filecontents)
				defender.AnalyzeFile()
			} else if targetengine == "amsi" || targetengine == "" {
				fmt.Println("[+] Start Checking with AMSI")
				amsi := NewAMSIInstance("")
				amsi.AnalyzeBytes(filecontents, "TestBuffer")
			} else {
				fmt.Println("[-] Input right Engine (AMSI or Defender)?")
				fmt.Println("[+] Start Checking with Default AMSI")
				amsi := NewAMSIInstance("")
				amsi.AnalyzeBytes(filecontents, "TestBuffer")
			}

		case 2: //Script
			fmt.Println("[+] Filetype is Script")
			if targetengine == "amsi" || targetengine == "" {
				fmt.Println("[+] Start Checking with AMSI")
				amsi := NewAMSIInstance("")
				amsi.AnalyzeBytes(filecontents, "TestBuffer")
			} else {
				fmt.Println("[-] Scripts cannot be detected by Defender")
				fmt.Println("[-] Input right Engine (AMSI or Defender)?")
				os.Exit(1)
			}
		default: //Unknown

			fmt.Println("[-]  Target file is unknown!")
			fmt.Println("[+] Start Checking with Default AMSI")
			amsi := NewAMSIInstance("")
			amsi.AnalyzeBytes(filecontents, "TestBuffer")

		}
	}
}
