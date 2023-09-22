package main

import (
	"time"

	"golang.org/x/sys/windows"
)

func main() {
	PROCESS_ALL_ACCESS := 0x1F0FFF
	time.Sleep(30 * time.Second)
	println("runn")
	pHandle, _ := windows.OpenProcess(uint32(PROCESS_ALL_ACCESS), false, 9340)
	windows.CloseHandle(pHandle)
}
