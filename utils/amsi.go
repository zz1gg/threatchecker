package utils

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	AMSI_RESULT_CLEAN        = 0
	AMSI_RESULT_NOT_DETECTED = 1
	AMSI_RESULT_DETECTED     = 32768
)

var (
	procAmsi           = syscall.NewLazyDLL("amsi.dll")
	procAmsiInitialize = procAmsi.NewProc("AmsiInitialize")
	//procAmsiUninitialize = procAmsi.NewProc("AmsiUninitialize")
	procAmsiOpenSession  = procAmsi.NewProc("AmsiOpenSession")
	procAmsiCloseSession = procAmsi.NewProc("AmsiCloseSession")
	procAmsiScanBuffer   = procAmsi.NewProc("AmsiScanBuffer")
)

type AmsiInstance struct {
	AmsiContext uintptr
	AmsiSession uintptr
	FileBytes   []byte
}

func NewAMSIInstance(appName string) *AmsiInstance {

	if appName == "" {
		appName = "PowerShell_C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe_5.1.22621.2506"
	}
	asmiContext, err := AmsiInitialize(appName)

	if err != nil {
		fmt.Printf("[-] Failed to initialize AMSI: %v\n", err)
		return nil
	}

	//Open AMSI session
	amsiSession, err := AmsiOpenSession(asmiContext)

	if err != nil {
		fmt.Printf("[-] Failed to open AMSI session: %v\n", err)
		return nil
	}
	return &AmsiInstance{
		AmsiContext: uintptr(asmiContext),
		AmsiSession: uintptr(amsiSession),
	}
}

type AMSIContext uintptr
type AMSISession uintptr

func (a *AmsiInstance) ScanWithAMSI(buffer []byte, contentName string) error {

	amsi := NewAMSIInstance("")

	defer AmsiCloseSession(AMSIContext(a.AmsiContext), AMSISession(a.AmsiSession))

	// Sample buffer to scan
	//str := "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

	result, err := amsi.AmsiScanBuffer(buffer, contentName)
	if err != nil {
		fmt.Printf("[-] Failed to scan buffer: %v \n", err)
		return err
	}

	switch result {
	case AMSI_RESULT_CLEAN:
		Malicious = false
		cyan.Println("[+] No threat found!")
	case AMSI_RESULT_NOT_DETECTED:
		cyan.Println("[+] No threat found!")
	case AMSI_RESULT_DETECTED:
		Malicious = true
		_, err := red.Println("[+] Threat found!")
		if err != nil {
			return err
		}

	default:
		yellow.Println("[+] Unknown reslut with:", result)

	}

	return nil
}

func (a *AmsiInstance) AmsiScanBuffer(buffer []byte, contentName string) (int, error) {
	var result int
	contentNamePtr, _ := syscall.UTF16PtrFromString(contentName)
	r1, _, err := procAmsiScanBuffer.Call(
		a.AmsiContext,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(contentNamePtr)),
		a.AmsiSession,
		uintptr(unsafe.Pointer(&result)),
	)
	if r1 != 0 {
		return 0, err
	}
	return result, nil
}

func AmsiInitialize(appName string) (AMSIContext, error) {
	var context AMSIContext
	appNamePtr, _ := syscall.UTF16PtrFromString(appName)
	r1, _, err := procAmsiInitialize.Call(uintptr(unsafe.Pointer(appNamePtr)), uintptr(unsafe.Pointer(&context)))
	if r1 != 0 {
		return 0, err
	}
	return context, nil
}

/*

func AmsiUninitialize(context AMSIContext) {
	procAmsiUninitialize.Call(uintptr(context))
}
*/

func AmsiOpenSession(context AMSIContext) (AMSISession, error) {
	var session AMSISession
	r1, _, err := procAmsiOpenSession.Call(uintptr(context), uintptr(unsafe.Pointer(&session)))
	if r1 != 0 {
		return 0, err
	}
	return session, nil
}

func AmsiCloseSession(context AMSIContext, session AMSISession) {
	_, _, err := procAmsiCloseSession.Call(uintptr(context), uintptr(session))
	if err != nil {
		return
	}
}

// Analyze bad bytes with amsi
func (a *AmsiInstance) AnalyzeBytes(bytes []byte, contentName string) {

	a.FileBytes = bytes

	status, _ := a.AmsiScanBuffer(a.FileBytes, contentName)
	//fmt.Println("[!] Defender Result Status code:", status)
	if status != AMSI_RESULT_DETECTED {
		cyan.Println("[+] No threat found!")
		return
	} else {
		Malicious = true
	}

	//fmt.Printf("[+] Target file size: %d bytes\n", len(a.FileBytes))
	fmt.Println("[+] AMSI Analyzing...")

	splitArray := make([]byte, len(a.FileBytes)/2)
	copy(splitArray, a.FileBytes[:len(a.FileBytes)/2])

	for !Complete {

		detectionStatus, _ := a.AmsiScanBuffer(splitArray, contentName)

		if detectionStatus == AMSI_RESULT_DETECTED {

			tmpArray := HalfSplitter(splitArray, lastgood)
			splitArray = make([]byte, len(tmpArray))
			copy(splitArray, tmpArray)
		} else {
			lastgood = len(splitArray)
			tmpArray := Overshot(a.FileBytes, len(splitArray))
			splitArray = make([]byte, len(tmpArray))
			copy(splitArray, tmpArray)
		}
	}
}
