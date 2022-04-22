SHELL = /bin/bash
GOBIN = $(shell go env GOPATH)/bin

test: 
	go test -race -v ./...

coverage:
	go test -race -covermode=atomic ./...

lint:
	golangci-lint run --verbose

bench: benchmark draw_benchmarks

benchmark:
	go test -benchmem -bench=. | tee bench/benchmark.txt

draw_benchmarks:
	$(GOBIN)/benchdraw --filter="BenchmarkRBAC" --title="RBAC-Benchmark" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/RBAC_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkRBAC" --title="RBAC-Benchmark Alloc" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/RBAC_alloc.svg

	$(GOBIN)/benchdraw --filter="BenchmarkABAC" --title="ABAC-Benchmark" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/ABAC_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkABAC" --title="ABAC-Benchmark Alloc" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/ABAC_alloc.svg

	$(GOBIN)/benchdraw --filter="BenchmarkAddPolicy" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/AddPolicy_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkAddPolicy" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/AddPolicy_alloc.svg

	$(GOBIN)/benchdraw --filter="BenchmarkRemovePolicy" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/RemovePolicy_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkRemovePolicy" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/RemovePolicy_alloc.svg