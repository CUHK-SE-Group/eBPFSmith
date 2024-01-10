package main

import (
	"github.com/cilium/ebpf/rlimit"
	"log"
)

func main() {
	codes := Generate()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("无法提升 memlock 限制: %v", err)
	}
	//metricUnit, cov := metric.NewMetric()
	//metric.EnableCoverage(cov)

	Validate(codes)

	//metricResults := metric.GetCoverageAndFreeResources(cov)
	//metricUnit.RecordVerificationResults(metricResults)
}
