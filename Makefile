SHELL = /bin/bash
GOBIN = $(shell go env GOPATH)/bin

bench: benchmark draw_benchmarks

benchmark:
	go test -benchmem -bench=. | tee bench/benchmark.txt

draw_benchmarks:
	$(GOBIN)/benchdraw --filter="BenchmarkRBAC" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/RBAC_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkRBAC" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/RBAC_alloc.svg

	$(GOBIN)/benchdraw --filter="BenchmarkABAC" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/ABAC_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkABAC" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/ABAC_alloc.svg

	$(GOBIN)/benchdraw --filter="BenchmarkAddPolicy" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/AddPolicy_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkAddPolicy" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/AddPolicy_alloc.svg