//go:build windows
package lib

import (
	"encoding/hex"
	"fmt"
	win "golang.org/x/sys/windows"
	"log"
	"strings"
	"time"
	"unsafe"
)


const (
	pFlagAll uint32 = 0x001F0FFF
	pFlagTerminate uint32 = 0x00000001
	pFlagCreateThread uint32 = 0x00000002
	pFlagVirtualMemoryOperation uint32 = 0x00000008
	pFlagVirtualMemoryRead uint32 = 0x00000010
	pFlagVirtualMemoryWrite uint32 = 0x00000020
	pFlagDuplicateHandle uint32 = 0x00000040
	pFlagCreateProcess uint32 = 0x000000080
	pFlagSetQuota uint32 = 0x00000100
	pFlagSetInformation uint32 = 0x00000200
	pFlagQueryInformation uint32 = 0x00000400
	pFlagQueryLimitedInformation uint32 = 0x00001000
	pFlagSynchronize uint32 = 0x00100000
)

//--MemoryPattern
type MemRegionSeq interface {isMatch(b uint8) bool}

type MatchMemRegionSeq struct {matchByte uint8}
type AnyMemRegionSeq struct {}

type MemPattern struct {Pattern []MemRegionSeq}

func (s MatchMemRegionSeq) isMatch(b uint8) bool {return s.matchByte==b}
func (s AnyMemRegionSeq) isMatch(b uint8) bool {return true}

func (s *MemPattern) New(pRegex string) { //pRegex - PseudoRegex
	parts := strings.Fields(pRegex)
	for _,part := range parts {
		if len(part)!=2 {log.Fatalf("Invalid regex sequence: %s in %s",part,parts)}
		if part=="??" {
			s.Pattern=append(s.Pattern,AnyMemRegionSeq{})
			continue
		}
		b,err_:=hex.DecodeString(part)
		if err_!=nil {log.Fatalf("Invalid regex sequence: %s in %s",part,parts)}
		s.Pattern=append(s.Pattern,MatchMemRegionSeq{b[0]})
	}
}
func (s MemPattern) ScanMemory(handle win.Handle, region win.MemoryBasicInformation) uintptr {
	patSize:=uintptr(len(s.Pattern))//unsafe.Sizeof(s)
	endAddr:= region.RegionSize - patSize
	buf:= make([]uint8,region.RegionSize)
	var bread uintptr
	//fmt.Println("patSize:",patSize,"| Addr:",region.BaseAddress,endAddr,"| RegionS:",region.RegionSize)
	err := win.ReadProcessMemory(handle,region.BaseAddress,&buf[0],region.RegionSize,&bread)
	if err!=nil {return 0}
	for addr:=uintptr(0);addr<endAddr;addr++ {
		sbuf:=make([]uint8,patSize)
		copy(sbuf,buf[addr:addr+uintptr(len(sbuf))])
		isFound:=true
		for i:=uintptr(0);i<patSize;i++ {
			if !s.Pattern[i].isMatch(sbuf[i]) {
				isFound=false
				break
			}
		}
		if isFound {return region.BaseAddress+addr}
	}
	return 0
}


//--MemoryPattern

func getPID(pName string) (uint32, error) {
	handle, err := win.CreateToolhelp32Snapshot(win.TH32CS_SNAPPROCESS,0)
	if err!=nil {return 0,err}
	const virtPE32Size = uint32(unsafe.Sizeof(win.ProcessEntry32{}))
	proc := win.ProcessEntry32{Size: virtPE32Size}
	for {
		err := win.Process32Next(handle, &proc)
		if err!=nil {return 0, err}
		if win.UTF16ToString(proc.ExeFile[:]) == pName { return proc.ProcessID, nil}
	}
}


func justWait(name string) uint32 {
	for {
		pid,err := getPID(name)
		if err!=nil {log.Println(err)}
		if pid>0 {return pid}
		time.Sleep(time.Second)
	}
}


func GetHandleForProcess(name string) win.Handle {
	pid:=justWait(name)
	fmt.Printf("Got PID %d for process %s\n",pid,name)
	handle,err:=win.OpenProcess(pFlagAll,false,pid)
	if err!=nil {log.Panicf("GetHandleW error: %s\n",err)}
	fmt.Printf("Got pHandle at 0x%X\n",handle)
	return handle
}

func QueryMemRegions(handle win.Handle) []win.MemoryBasicInformation {
	var curPos uintptr = 0
	var lRegions []win.MemoryBasicInformation

	for {
		var memregion win.MemoryBasicInformation
		err := win.VirtualQueryEx(handle,curPos,&memregion,unsafe.Sizeof(memregion))
		if err!=nil {break}
		//fmt.Printf("0x%X %b\n",memregion.State,memregion.Protect&0x100)
		if (memregion.State & 0x1000)!=0 && (memregion.Protect & 0x100)==0 { //0x2 0x104 0x20 0x40 0x8 ok
			lRegions = append(lRegions,memregion)
		}
		curPos = memregion.BaseAddress + memregion.RegionSize
	}
	return lRegions
}

func ScanPattern(handle win.Handle, pattern MemPattern) uintptr {
	regions:=QueryMemRegions(handle)
	fmt.Println("Got regions:",len(regions))
	for _,memReg:= range regions {
		addr:=pattern.ScanMemory(handle,memReg)
		if addr==0 {continue}
		return addr
	}
	return 0
}

func ReadMem(handle win.Handle, addr, size uintptr) []uint8{
	buf:= make([]uint8,size)
	var bread uintptr
	err := win.ReadProcessMemory(handle,addr,&buf[0],size,&bread)
	if err!=nil {
		log.Printf("ReadProcessMemoryW error: %s\n",err)
		return make([]uint8,0)
	}
	return buf
}

func WriteMem(handle win.Handle, addr, size uintptr,value []uint8) {
	var bread uintptr
	err:= win.WriteProcessMemory(handle,addr,&value[0],size,&bread)
	if err!=nil {
		log.Printf("WriteProcessMemoryW error: %s\n",err)
	}
}