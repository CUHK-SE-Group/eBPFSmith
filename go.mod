module ebpf-generator

go 1.21.1

replace (
	github.com/CUHK-SE-Group/generic-generator v0.0.0-20240111040354-4459d0783638 => ../generic-generator
)

require (
	github.com/CUHK-SE-Group/generic-generator v0.0.0-20240111040354-4459d0783638
	github.com/cilium/ebpf v0.9.3
	github.com/google/safehtml v0.1.0
	gvisor.dev/gvisor v0.0.0-20240109032559-fc0349e3ac32
)

require (
	github.com/IBM/fp-go v1.0.56 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.0 // indirect
	github.com/hashicorp/go-memdb v1.3.4 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/lucasjones/reggen v0.0.0-20200904144131-37ba4fa293bb // indirect
	golang.org/x/exp v0.0.0-20230725093048-515e97ebf090 // indirect
	golang.org/x/sys v0.14.1-0.20231108175955-e4099bfacb8c // indirect
	golang.org/x/text v0.13.0 // indirect
	golang.org/x/time v0.3.0 // indirect
)
