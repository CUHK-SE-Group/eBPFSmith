package metric

import (
	"os"
	"reflect"
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
	Fd             int
	CoverageSize   int
	CoverageBuffer []uint64
}

func EnableCoverage(coverageInfo *CoverageData) {
	fd, err := os.OpenFile("/sys/kernel/debug/kcov", os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	defer fd.Close()

	coverageInfo.Fd = int(fd.Fd())
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(coverageInfo.Fd), uintptr(KCOV_INIT_TRACE), uintptr(coverageInfo.CoverageSize))
	if errno != 0 {
		panic(errno)
	}

	buffer, err := syscall.Mmap(coverageInfo.Fd, 0, coverageInfo.CoverageSize*8, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		panic(err)
	}

	// Convert the byte slice to a uint64 slice with the correct capacity and length.
	header := (*reflect.SliceHeader)(unsafe.Pointer(&buffer))
	header.Len /= 8
	header.Cap /= 8
	coverageInfo.CoverageBuffer = *(*[]uint64)(unsafe.Pointer(header))

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(coverageInfo.Fd), uintptr(KCOV_ENABLE), uintptr(KCOV_TRACE_PC))
	if errno != 0 {
		panic(errno)
	}

	// Initialize the first element of coverage buffer to zero.
	coverageInfo.CoverageBuffer[0] = 0
}

func GetCoverageAndFreeResources(coverageInfo *CoverageData) *ValidationResult {
	if coverageInfo.Fd == -1 {
		panic("Fd == -1")
	}
	traceSize := coverageInfo.CoverageBuffer[0]
	seenAddress := make(map[uint64]bool)
	for i := uint64(0); i < traceSize; i++ {
		addr := coverageInfo.CoverageBuffer[i+1]
		if _, exists := seenAddress[addr]; !exists {
			// Add to coverage addresses
			seenAddress[addr] = true
		}
	}
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(coverageInfo.Fd), uintptr(KCOV_DISABLE), 0)
	syscall.Close(coverageInfo.Fd)

	// Convert CoverageBuffer back to byte slice for Munmap
	byteSliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&coverageInfo.CoverageBuffer))
	byteSliceHeader.Len *= 8 // sizeof(uint64)
	byteSliceHeader.Cap *= 8 // sizeof(uint64)
	syscall.Munmap(*(*[]byte)(unsafe.Pointer(byteSliceHeader)))

	var address []uint64

	for k, v := range seenAddress {
		if v == true {
			address = append(address, uint64(k))
		}
	}
	return &ValidationResult{
		IsValid:            false,
		DidCollectCoverage: true,
		CoverageAddress:    address,
		CoverageData:       coverageInfo,
	}
}
