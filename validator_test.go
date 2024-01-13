package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestValidate(t *testing.T) {
	hexStrings := []string{
		"8723000000000000",
		"B700000000000000",
		"9500000000000000",
	}

	// 初始化一个uint64类型的数组，长度与字符串数组相同
	var instructions []uint64
	// 遍历16进制字符串数组，并将每个值转换为uint64
	for _, hexStr := range hexStrings {
		// 使用ParseUint转换16进制字符串，64是位数，16是基数
		value, err := strconv.ParseUint(hexStr, 16, 64)
		if err != nil {
			// 如果发生错误，打印错误并退出
			fmt.Printf("Error converting %s: %s\n", hexStr, err)
			return
		}
		// 将转换后的值添加到uint64数组
		instructions = append(instructions, value)
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
		fmt.Println(err)
	}
	defer prog.Close()

}
