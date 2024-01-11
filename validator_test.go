package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestValidate(t *testing.T) {
	instructions := []uint64{
		7639445453340661378,
		13186539708940812288,
		10736581511651262464,
	}
	fmt.Printf("\nuint64 format instruction:")
	buf := new(bytes.Buffer)
	for _, instr := range instructions {
		fmt.Printf("\n%v", instr)
		if err := binary.Write(buf, binary.BigEndian, instr); err != nil {
			log.Fatalf("无法写入指令: %v", err)
		}
	}
	fmt.Println()
	ins := asm.Instructions{}
	err := ins.Unmarshal(buf, binary.BigEndian)
	if err != nil {
		panic(err)
	}

	progSpec := &ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: ins,
	}
	fmt.Printf("\n\ninstruction lists:\n%v\n", progSpec.Instructions)
	prog, err := ebpf.NewProgramWithOptions(progSpec, ebpf.ProgramOptions{
		LogLevel: ebpf.LogLevelInstruction | ebpf.LogLevelStats,
	})

	if err == nil {
		fmt.Println("verifier log: ", prog.VerifierLog)
	} else {
		panic(err)
	}
	defer prog.Close()

}
