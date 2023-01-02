package lib

import (
	pe2 "debug/pe"
	"github.com/saferwall/pe"
	win "golang.org/x/sys/windows"
	"log"
	"path/filepath"
	"time"
	"unsafe"
)

var (
	kern32         = win.NewLazyDLL("kernel32.dll")
	createProcess  = kern32.NewProc("CreateProcessA")
	virtualAllocEx = kern32.NewProc("VirtualAllocEx")
	virtualFreeEx  = kern32.NewProc("VirtualFreeEx")
)

func CreateProcess(path string) (win.ProcessInformation, error) {
	log.Println("Creating process: ", path)
	var si win.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi win.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	//CreateProcessA
	err := win.CreateProcess(nil, win.StringToUTF16Ptr(path), nil, nil, false, win.CREATE_SUSPENDED, nil, nil, &si, &pi)
	return pi, err
}

func PatchEntryPoint(h win.Handle, dllPath string) error {
	var pb win.PROCESS_BASIC_INFORMATION
	log.Println("Getting base address")
	err := win.NtQueryInformationProcess(h,
		win.ProcessBasicInformation,
		unsafe.Pointer(&pb),
		uint32(unsafe.Sizeof(pb)),
		nil)
	if err != nil {
		return err
	}

	// get exe base address from pb
	exeBase := pb.PebBaseAddress.ImageBaseAddress + 8 //! Not sure what is +8
	// get entry point from exe base
	var entryPoint byte
	err = win.ReadProcessMemory(h, exeBase, &entryPoint, 4, nil)
	if err != nil {
		return err
	}

	log.Println("Readeing PE headers")
	var dosHeaderB byte
	err = win.ReadProcessMemory(h, uintptr(entryPoint), &dosHeaderB, 64, nil)
	if err != nil {
		return err
	}
	dosHeader := (*pe.ImageDOSHeader)(unsafe.Pointer(&dosHeaderB))

	//get nt headers
	var ntHeadersB byte
	err = win.ReadProcessMemory(h, uintptr(entryPoint)+uintptr(dosHeader.AddressOfNewEXEHeader), &ntHeadersB, 64, nil)
	if err != nil {
		return err
	}
	ntHeaders := (*pe.ImageNtHeader)(unsafe.Pointer(&ntHeadersB))

	OrigNTHeaders := *ntHeaders

	//Allocate new buffer for dll
	//dllPath, err = win.UTF16PtrFromString(dllPath)
	//if err != nil {
	//	return err
	//}

	log.Println("Allocating memory for dll path")

	r1, _, err := virtualAllocEx.Call(uintptr(h), 0, uintptr(len(dllPath)), win.MEM_COMMIT|win.MEM_RESERVE, win.PAGE_READWRITE)
	if r1 == 0 {
		return err
	}
	dllPathAddr := r1
	err = win.WriteProcessMemory(h, dllPathAddr, (*byte)(unsafe.Pointer(&dllPath)), uintptr(len(dllPath)), nil)
	if err != nil {
		return err
	}

	lookupTable := []uint32{0x80000001, 0}

	//Alloc memory for lookup table
	r1, _, err = virtualAllocEx.Call(uintptr(h), 0, unsafe.Sizeof(lookupTable), win.MEM_COMMIT|win.MEM_RESERVE, win.PAGE_READWRITE)
	if r1 == 0 {
		return err
	}
	lookupTableAddr := r1

	//Write lookup table
	err = win.WriteProcessMemory(h, lookupTableAddr, (*byte)(unsafe.Pointer(&lookupTable)), unsafe.Sizeof(lookupTable), nil)
	if err != nil {
		return err
	}

	//Allocate buffer for new lookup table
	r1, _, err = virtualAllocEx.Call(uintptr(h), 0, unsafe.Sizeof(lookupTable), win.MEM_COMMIT|win.MEM_RESERVE, win.PAGE_READWRITE)
	if r1 == 0 {
		return err
	}
	lookupTableAddr = r1

	//Write lookup table
	err = win.WriteProcessMemory(h, lookupTableAddr, (*byte)(unsafe.Pointer(&lookupTable)), unsafe.Sizeof(lookupTable), nil)
	if err != nil {
		return err
	}

	NewDllImportDescriptors := []pe.ImageImportDescriptor{
		{
			OriginalFirstThunk: uint32(lookupTableAddr) - uint32(entryPoint),
			TimeDateStamp:      0,
			ForwarderChain:     0,
			Name:               uint32(dllPathAddr) - uint32(entryPoint),
			FirstThunk:         uint32(lookupTableAddr) - uint32(entryPoint),
		},
		{
			OriginalFirstThunk: 0,
			TimeDateStamp:      0,
			ForwarderChain:     0,
			Name:               0,
			FirstThunk:         0,
		},
	}

	existingImportDescriptorEntryCount := ntHeaders.OptionalHeader.(*pe2.OptionalHeader32).DataDirectory[pe2.IMAGE_DIRECTORY_ENTRY_IMPORT].Size / uint32(unsafe.Sizeof(pe.ImageImportDescriptor{}))
	var newImportDescriptorCount uint32 = 0
	if existingImportDescriptorEntryCount == 0 {
		newImportDescriptorCount = 2
	} else {
		newImportDescriptorCount = existingImportDescriptorEntryCount + 1
	}

	//Allocate buffer for new import descriptor
	descriptorDataLength := newImportDescriptorCount * uint32(unsafe.Sizeof(pe.ImageImportDescriptor{}))
	if existingImportDescriptorEntryCount != 0 {
		// read exising import descriptor entries
		var newImportDescriptorEntriesB byte
		existingImportDescriptorAddr := uint32(entryPoint) + ntHeaders.OptionalHeader.(*pe2.OptionalHeader32).DataDirectory[pe2.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
		err = win.ReadProcessMemory(h, uintptr(existingImportDescriptorAddr), &newImportDescriptorEntriesB, uintptr(existingImportDescriptorEntryCount*uint32(unsafe.Sizeof(pe.ImageImportDescriptor{}))), nil)
		if err != nil {
			return err
		}
	}
	//Copy new dll import
	//copyImportDescriptionDataPtr := uint32(unsafe.Sizeof(NewDllImportDescriptors)) + descriptorDataLength - uint32(unsafe.Sizeof(pe.ImageImportDescriptor{}))

	// Allocate buffer for new import descriptor
	r1, _, err = virtualAllocEx.Call(uintptr(h), 0, uintptr(descriptorDataLength), win.MEM_COMMIT|win.MEM_RESERVE, win.PAGE_READWRITE)
	if r1 == 0 {
		return err
	}
	newImportDescriptorAddr := r1
	err = win.WriteProcessMemory(h, newImportDescriptorAddr, (*byte)(unsafe.Pointer(&NewDllImportDescriptors)), uintptr(descriptorDataLength), nil)
	if err != nil {
		return err
	}

	log.Println("Updating PE Headers...")
	//Update PE headers
	ntHeaders.OptionalHeader.(*pe2.OptionalHeader32).DataDirectory[pe2.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = uint32(newImportDescriptorAddr) - uint32(entryPoint)
	ntHeaders.OptionalHeader.(*pe2.OptionalHeader32).DataDirectory[pe2.IMAGE_DIRECTORY_ENTRY_IMPORT].Size = descriptorDataLength

	var oldProtect uint32
	err = win.VirtualProtectEx(h, uintptr(entryPoint)+uintptr(dosHeader.AddressOfNewEXEHeader), 64, win.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return err
	}

	err = win.WriteProcessMemory(h, uintptr(entryPoint)+uintptr(dosHeader.AddressOfNewEXEHeader), (*byte)(unsafe.Pointer(ntHeaders)), 64, nil)
	if err != nil {
		return err
	}

	log.Println("Resuming process")
	//Resume process
	win.ResumeThread(h)
	log.Println("Waiting for DLL")
	for {
		newLookupTable := make([]uint32, 2)
		err = win.ReadProcessMemory(h, lookupTableAddr, (*byte)(unsafe.Pointer(&newLookupTable)), unsafe.Sizeof(newLookupTable), nil)
		if err != nil {
			return err
		}
		if newLookupTable[0] == lookupTable[0] {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		break
	}
	log.Println("Restoring original PE headers")
	//Restore original PE headers
	err = win.WriteProcessMemory(h, uintptr(entryPoint)+uintptr(dosHeader.AddressOfNewEXEHeader), (*byte)(unsafe.Pointer(&OrigNTHeaders)), 64, nil)
	if err != nil {
		return err
	}
	// restore original protection
	oldProtect2 := uint32(0)
	err = win.VirtualProtectEx(h, uintptr(entryPoint)+uintptr(dosHeader.AddressOfNewEXEHeader), 64, oldProtect, &oldProtect2)
	if err != nil {
		return err
	}

	// Free everything
	virtualFreeEx.Call(uintptr(h), lookupTableAddr, 0, win.MEM_RELEASE)
	virtualFreeEx.Call(uintptr(h), dllPathAddr, 0, win.MEM_RELEASE)
	virtualFreeEx.Call(uintptr(h), newImportDescriptorAddr, 0, win.MEM_RELEASE)
	return nil
}

func PreInjectDLL(procName string, dll string) {

	//get process full path
	procPath, err := filepath.Abs(procName)
	if err != nil {
		log.Fatal(err)
	}

	//Create process
	pi, err := CreateProcess(procPath)
	if err != nil {
		panic(err)
	}
	//get dll full path
	dllPath, err := filepath.Abs(dll)
	if err != nil {
		panic(err)
	}
	//Inject dll
	err = PatchEntryPoint(pi.Process, dllPath)
	if err != nil {
		log.Println(err)
	}
}
