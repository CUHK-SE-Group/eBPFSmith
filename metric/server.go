package metric

import "fmt"
import "os/exec"

func NewMetric() (*Metrics, *CoverageData) {
	cov := &CoverageData{
		CoverageSize: 1024,
		Fd:           -1,
	}
	vmLinuxPath := "/home/nn/vmlinux"
	mgr := NewCoverageManagerImpl(func(inputString string) (string, error) {
		cmd := exec.Command("/usr/bin/addr2line", "-e", vmLinuxPath)
		w, err := cmd.StdinPipe()
		if err != nil {
			return "", err
		}
		w.Write([]byte(inputString))
		w.Close()
		outBytes, err := cmd.CombinedOutput()
		fmt.Println(string(outBytes))
		return string(outBytes), err
	})

	metricUnit := NewMetricsUnit(1, 1, vmLinuxPath, "/home/nn/linux/kernel/bpf", "0.0.0.0", 9999, mgr)
	return metricUnit, cov
}
