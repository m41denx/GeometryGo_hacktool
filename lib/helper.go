package lib

import (
	"bytes"
	"os"
	"strings"
)

func VerifyGeometryDash(fname string) bool {
	fh,err := os.Open(fname)
	if err!=nil {return false}
	if !strings.HasSuffix(fh.Name(),".exe") {return false}
	fs, _ :=fh.Stat()
	if fs.Size()>1024*1024*16 {
		//Definetely not GD, too big to read anyways
		return false
	}
	gdBytes:= make([]uint8,fs.Size())
	_, err = fh.Read(gdBytes)
	if err!=nil {return false}
	//Search specific bytes in GD binary to verify it

	if bytes.LastIndex(gdBytes,[]uint8("?AVGManager@@"))<0 || bytes.LastIndex(gdBytes,[]uint8(".?AVAccountLayer@@"))<0 ||
		bytes.LastIndex(gdBytes,[]uint8(".?AVGJScaleControlDelegate@@"))<0 || bytes.LastIndex(gdBytes,[]uint8("rubrubpowah123"))<0 {
			return false
	}
	return true
}


func DetectGeometryDashExec() string {
	flist,err := os.ReadDir("./")
	if err!=nil {return ""}
	for _, fname := range flist {
		if fname.IsDir() || !strings.HasSuffix(fname.Name(),".exe") {continue}
		return fname.Name()
	}
	return ""
}
