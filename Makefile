SHELL = /bin/bash
GOBIN = $(shell go env GOPATH)/bin

test: 
	go test -race ./...

coverage:
	go test -race -covermode=atomic ./...

lint:
	golangci-lint run --verbose

bench: benchmark draw_benchmarks

benchmark:
	go test -benchmem -bench=. | tee bench/benchmark.txt

draw_benchmarks:
	$(GOBIN)/benchdraw --filter="BenchmarkCmpRBAC" --title="Enforce RBAC" --x=users_roles_objects --group=enforcer < ./bench/benchmark.txt > ./bench/RBAC_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkCmpRBAC" --title="Enforce RBAC Alloc" --x=users_roles_objects --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/RBAC_alloc.svg

	$(GOBIN)/benchdraw --filter="BenchmarkCmpABAC" --title="Enforce ABAC" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/ABAC_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkCmpABAC" --title="Enforce ABAC Alloc" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/ABAC_alloc.svg

	$(GOBIN)/benchdraw --filter="BenchmarkCmpAddPolicy" --title="Add Rule" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/AddPolicy_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkCmpAddPolicy" --title="Add Rule Alloc" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/AddPolicy_alloc.svg

	$(GOBIN)/benchdraw --filter="BenchmarkCmpRemovePolicy" --title="Remove Rule" --x=size --group=enforcer < ./bench/benchmark.txt > ./bench/RemovePolicy_op.svg
	$(GOBIN)/benchdraw --filter="BenchmarkCmpRemovePolicy" --title="Remove Rule Alloc" --x=size --group=enforcer --y=allocs/op < ./bench/benchmark.txt > ./bench/RemovePolicy_alloc.svg

	$(GOBIN)/benchdraw --filter="BenchmarkCmpPathMatch" --title="Matching Function" --x=name --group=pkg < ./bench/benchmark.txt > ./bench/PathMatch_op.svg