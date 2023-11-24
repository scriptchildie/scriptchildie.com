package main

import "C" // Cgo is required to compile a dll
import "golang.org/x/sys/windows"

// This code will execute before any other function executes
func init() {
	windows.MessageBox(
		windows.HWND(0),
		windows.StringToUTF16Ptr("init loaded"),
		windows.StringToUTF16Ptr("Success"),
		0x0,
	)
}

//Exported functions should have the following comment right before the function
//export Test
func Test() {
	windows.MessageBox(
		windows.HWND(0),
		windows.StringToUTF16Ptr("Exported test() function loaded"),
		windows.StringToUTF16Ptr("Success"),
		0x0,
	)
}

// doesn't really do anything but it's needed to compile
func main() {

}
