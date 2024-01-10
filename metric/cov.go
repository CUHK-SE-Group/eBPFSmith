package metric

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

var (
	KCOV_INIT_TRACE = linux.KCOV_INIT_TRACE
	KCOV_ENABLE     = linux.KCOV_ENABLE
	KCOV_DISABLE    = linux.KCOV_DISABLE
	KCOV_TRACE_PC   = linux.KCOV_TRACE_PC
	KCOV_TRACE_CMP  = linux.KCOV_TRACE_CMP
)

type CoverageData struct {
	fd             int
	coverageSize   int
	coverageBuffer []byte
}

func enableCoverage(coverageInfo *CoverageData) {
	fd, err := os.OpenFile("/sys/kernel/debug/kcov", os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	coverageInfo.fd = int(fd.Fd())
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(coverageInfo.fd), uintptr(KCOV_INIT_TRACE), uintptr(coverageInfo.coverageSize))
	if errno != 0 {
		panic(errno)
	}
	fmt.Println(coverageInfo.fd)
	buffer, err := syscall.Mmap(coverageInfo.fd, 0, coverageInfo.coverageSize*8, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		panic(err)
	}
	coverageInfo.coverageBuffer = (*[1 << 30]byte)(unsafe.Pointer(&buffer[0]))[:coverageInfo.coverageSize:coverageInfo.coverageSize]
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(coverageInfo.fd), uintptr(KCOV_ENABLE), uintptr(KCOV_TRACE_PC))
	if errno != 0 {
		panic(errno)
	}
	coverageInfo.coverageBuffer[0] = 0
}

func getCoverageAndFreeResources(coverageInfo *CoverageData) {
	if coverageInfo.fd == -1 {
		panic("fd == -1")
	}
	traceSize := coverageInfo.coverageBuffer[0]
	seenAddress := make(map[byte]bool)
	for i := uint64(0); i < uint64(traceSize); i++ {
		addr := coverageInfo.coverageBuffer[i+1]
		if _, exists := seenAddress[addr]; !exists {
			// Add to coverage addresses
			seenAddress[addr] = true
		}
	}
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(coverageInfo.fd), uintptr(KCOV_DISABLE), 0)
	syscall.Close(coverageInfo.fd)
	syscall.Munmap(coverageInfo.coverageBuffer)
}
