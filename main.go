package main

import (
	"geometrygo/lib"
)

//So if you want to use it as external cheat - x64
//If you want to inject DLLs - x86

func main() {
	//if len(os.Args) < 2 {
	//	fmt.Println("Drag and drop GD executable on Cheat")
	//	os.Exit(1)
	//}
	//fname := filepath.Base(os.Args[1])
	//if !lib.VerifyGeometryDash(os.Args[1]) {
	//	fmt.Printf("%s Verification not passed", fname)
	//	os.Exit(1)
	//}

	//mp := lib.MemPattern{}
	//regex := "FF 00 00 00 00 ?? ?? 24 E4 ?? ??"
	//mp.New(regex)
	//addr := lib.ScanPattern(hand, mp)
	//fmt.Printf("Got Match Addr on 0x%X\n", addr)
	//fmt.Println("Value Got from there:")
	//for _, val := range lib.ReadMem(hand, addr+15, 4) {
	//	fmt.Printf("%X ", val)
	//}
	//fmt.Println()
	////var value = []uint8{0x0D, 0x00, 0x00, 0x00}
	//for {
	//	fmt.Printf("\rCurrent objects: %d     ", binary.LittleEndian.Uint32(lib.ReadMem(hand, addr+15, 4)))
	//	//lib.WriteMem(hand, addr+15, 4, value)
	//	time.Sleep(100 * time.Millisecond)
	//}

	lib.PreInjectDLL("C:\\Users\\m41den\\Desktop\\xHydra\\xHydra.exe", "C:\\Users\\m41den\\Desktop\\xHydra\\hello-world-x86.dll")
}
