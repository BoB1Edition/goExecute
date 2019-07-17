package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/gotk3/gotk3/gtk"
)

type word [2]byte
type dword [4]byte

type MZHeader struct {
	Magic             word
	ExtraBytes        word
	Pages             word
	RelocationItems   word
	HeaderSize        word
	MinimumAllocation word
	MaximumAllocation word
	InitialSS         word
	InitialSP         word
	Checksum          word
	InitialIP         word
	InitialCS         word
	RelocationTable   word
	Overlay           word
	E_res1            [4]word
	Oemid             word
	Oeminfo           word
	E_res2            [10]word
	E_lfanew          dword
}

type PEHeader struct {
	//Data []byte
}

type EXEstruct struct {
	*MZHeader
	*PEHeader
	//Data []byte
}

func (word *word) toUint16() uint16 {
	//t := []byte{word[0], word[1]}
	ret := binary.LittleEndian.Uint16([]byte{word[0], word[1]})
	return ret
}

func (dword *dword) toUint32() uint32 {
	ret := binary.LittleEndian.Uint32([]byte{dword[0], dword[1], dword[2], dword[3]})
	return ret
}

func (mzheader *MZHeader) isPE() bool {

	if ([2]byte{77, 90}) == mzheader.Magic {
		return true
	}
	return false
}

func main() {
	gtk.Init(nil)
	//gtk.
	//win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
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
	binary.Read(bytes.NewReader(data), binary.LittleEndian, &mzheader)
	fmt.Println("Magic: ", execute.Magic)
	fmt.Println("IP: ", execute.InitialIP.toUint16())
	fmt.Println("CS: ", execute.InitialCS)
	fmt.Println("SP: ", execute.InitialSP)
	fmt.Println("SS: ", execute.InitialSS)
	fmt.Println("RelocationTable: ", execute.RelocationTable.toUint16())
	fmt.Println("E_lfanew: ", execute.E_lfanew.toUint32())
	fmt.Println("mzheader: ", mzheader)
}
