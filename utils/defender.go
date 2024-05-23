package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type ScanResult int

const (
	NoThreatFound ScanResult = iota
	ThreatFound
	FileNotFound
	Timeout
	Error
)

type DefenderScanResult struct {
	Result    ScanResult
	Signature string
}

type Defender struct {
	FileBytes []byte
	FilePath  string
}

func NewDefender(fileBytes []byte) *Defender {
	return &Defender{
		FileBytes: fileBytes,
	}
}

func (d *Defender) AnalyzeFile() *DefenderScanResult {
	tempDir := "C:\\Temp"
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		os.Mkdir(tempDir, os.ModePerm)

	}

	tempFilePath := filepath.Join(tempDir, "file.exe")
	err := os.WriteFile(tempFilePath, d.FileBytes, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return &DefenderScanResult{Result: Error}
	}
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
		}
	}(tempFilePath)

	status := d.ScanFile(tempFilePath)

	switch status.Result {
	case NoThreatFound:
		Malicious = false
		cyan.Println("[+] No threat found!(Defender)")
	case ThreatFound:
		Malicious = true
		red.Println("[!] Threat found!(Defender)")
		red.Println("[!] Threat Signature: ", status.Signature)
		fmt.Println("[+] Defender Analyzing...")
		fileBytes := d.FileBytes
		splitArray := make([]byte, len(fileBytes)/2)
		copy(splitArray, fileBytes[:len(fileBytes)/2])
		lastgood := 0
		for !Complete {

			//fmt.Printf("Testing %d bytes\n", len(splitArray))
			err := os.WriteFile(tempFilePath, splitArray, 0644)
			if err != nil {
				fmt.Println("[-] Error writing file:", err)
				//return &DefenderScanResult{Result: Error}
			}
			detectionstatus := d.ScanFile(tempFilePath)
			if detectionstatus.Result == ThreatFound {
				//fmt.Println("[+] Threat found with Defender, splitting...")
				//splitArray = splitArray[:len(splitArray)/2]
				tmpArray := HalfSplitter(splitArray, lastgood)
				splitArray = make([]byte, len(tmpArray))
				copy(splitArray, tmpArray)

			} else if detectionstatus.Result == NoThreatFound {
				//fmt.Println("[-] No threat found, increasing size(Defender)")

				lastgood = len(splitArray)
				tmpArray := Overshot(d.FileBytes, len(splitArray))
				splitArray = make([]byte, len(tmpArray))
				copy(splitArray, tmpArray)

			} else {
				Complete = true
			}
		}

	case FileNotFound:
		fmt.Println("[-] File not found!(Defender)")
	case Timeout:
		fmt.Println("[-] Scan timed out!(Defender)")
	case Error:
		fmt.Println("[-] Error occurred during scan!")

	}

	return status
}

func (d *Defender) ScanFile(filePath string) *DefenderScanResult {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return &DefenderScanResult{Result: FileNotFound}
	}

	var cmd = `C:\Windows\system32\cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File ` + filePath + ` -DisableRemediation -Trace -Level 0x10`

	var comSpec = os.Getenv("COMSPEC")
	if comSpec == "" {
		comSpec = os.Getenv("SystemRoot") + "\\System32\\cmd.exe"
	}

	childProcess := exec.Command(comSpec)
	childProcess.SysProcAttr = &syscall.SysProcAttr{CmdLine: comSpec + " /C \"" + cmd + "\""}

	var stdout, stderr bytes.Buffer
	childProcess.Stdout = &stdout
	childProcess.Stderr = &stderr

	err := childProcess.Start()
	if err != nil {
		fmt.Println("[-] Defender Error starting command:", err)
		return &DefenderScanResult{Result: Error}
	}

	done := make(chan error, 1)
	go func() {
		done <- childProcess.Wait()
	}()

	select {
	case <-time.After(30 * time.Second):
		if err := childProcess.Process.Kill(); err != nil {
			fmt.Println("[-] Failed to kill process(Defender):", err)
		}

		//fmt.Println("[-] Process killed as timeout reached(Defender)")
		//fmt.Println("[-] Defender Output:", stdout.String())
		//fmt.Println("[-] Defender Error Output:", stderr.String())
		return &DefenderScanResult{Result: Timeout}
	case err := <-done:
		output := stdout.String()
		if err != nil {

			//fmt.Printf("[-] Output:\n%s\n", stdout.String())

			if childProcess.ProcessState.ExitCode() == 2 {
				//fmt.Println("[+] Threats detected with Defender")
				lines := strings.Split(output, "\n")
				var sigName string

				for _, line := range lines {
					if strings.Contains(line, "Threat  ") {
						sig := strings.Split(line, " ")
						if len(sig) >= 20 {
							sigName = sig[19]
							break
						}
					}
				}
				//fmt.Println("[+] Threat Signature With Defender:", sigName)
				Malicious = true
				return &DefenderScanResult{Result: ThreatFound, Signature: sigName}
			}
			return &DefenderScanResult{Result: Error}
		} else if childProcess.ProcessState.ExitCode() == 0 {
			//fmt.Println("[+] No threats detected with Defender")
			Malicious = false
			return &DefenderScanResult{Result: NoThreatFound}
		} else {
			//fmt.Println("[+] Defender Error: ", err)
			//fmt.Println("[+] ", output)
			//Malicious = false
			return &DefenderScanResult{Result: Error}

		}

	}

}
