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
	var instructions []uint64
	for _, code := range codes {
		fmt.Println(BinaryToHex(code))

		instruction, err := BinaryStringToUint64(code)
		if err != nil {
			panic(err)
		}
		instructions = append(instructions, instruction)
	}

	// 将 uint64 数组转换为字节序列
	buf := new(bytes.Buffer)
	for _, instr := range instructions {
		fmt.Println(instr)
		if err := binary.Write(buf, binary.BigEndian, instr); err != nil {
			log.Fatalf("无法写入指令: %v", err)
		}
	}
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
	fmt.Println(progSpec.Instructions)
	prog, err := ebpf.NewProgramWithOptions(progSpec, ebpf.ProgramOptions{
		LogLevel: ebpf.LogLevelInstruction,
	})

	if err != nil {
		log.Fatalf("加载 eBPF 程序失败: %v", err)
	}
	defer prog.Close()
	fmt.Println("verifier log: ", prog.VerifierLog)
}
