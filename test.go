package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
)

type word [2]byte

type MZHeader struct {
	Magic              word
	ExtraBytes         word
	Pages              word
	RelocationItems    word
	HeaderSize         word
	MinimumAllocation  word
	MaximumAllocation  word
	InitialSS          word
	InitialSP          word
	Checksum           word
	InitialIP          word
	InitialCS          word
	RelocationTable    word
	Overlay            word
	OverlayInformation word
}

type PEHeader struct {
	Data []byte
}

type EXEstruct struct {
	*MZHeader
	*PEHeader
	Data []byte
}

func (mzheader *MZHeader) isPE() bool {

	if ([2]byte{77, 90}) == mzheader.Magic {
		return true
	}
	return false
}

func main() {
	pathEXE := flag.String("pathEXE", "c:\\windows\\notepad.exe", "path to disasamble execute")
	flag.Parse()
	data, err := ioutil.ReadFile(*pathEXE)
	if err != nil {
		fmt.Printf("Execute file %s not read\n", *pathEXE)
		return
	}
	mzheader := MZHeader{}
	peheader := PEHeader{}
	execute := EXEstruct{}
	execute.MZHeader = &mzheader
	execute.PEHeader = &peheader
	binary.Read(bytes.NewReader(data), binary.BigEndian, &mzheader)
	fmt.Println("magic: ", execute.Magic)

}
