package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"log"
)

func Validate(codes []string) {
	fmt.Println("========================================validating log========================================")
	var instructions []uint64

	for _, code := range codes {
		h, _ := BinaryToHex(code)
		fmt.Printf("\n%v", h)

		instruction, err := BinaryStringToUint64(code)
		if err != nil {
			panic(err)
		}
		instructions = append(instructions, instruction)
	}
	fmt.Println()
	// 将 uint64 数组转换为字节序列
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
	}
	defer prog.Close()
}
