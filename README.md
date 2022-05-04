<p align="center">
<img src="logo.png" alt="FastAC">
</p>
<p align="center">
    <em>access control for go, supports RBAC, ABAC and ACL, drop-in replacement for casbin</em>
</p>

[![Test](https://github.com/abichinger/fastac/actions/workflows/test.yml/badge.svg?branch=main)](https://codecov.io/gh/abichinger/fastac)
[![Coverage](https://img.shields.io/codecov/c/github/abichinger/fastac)](https://codecov.io/gh/abichinger/fastac)
[![Go Report Card](https://goreportcard.com/badge/github.com/abichinger/fastac)](https://goreportcard.com/report/github.com/abichinger/fastac)
[![Godoc](https://godoc.org/github.com/abichinger/fastac?status.svg)](https://pkg.go.dev/github.com/abichinger/fastac)

FastAC is a drop in replacement for [Casbin](https://github.com/casbin/casbin). In some cases, FastAC can improve the [performance](#performance-comparison) significantly.

API documentation: [https://pkg.go.dev/github.com/abichinger/fastac](https://pkg.go.dev/github.com/abichinger/fastac)

Please refer to the [Casbin Docs](https://casbin.org/docs/en/how-it-works) for explanation of terms.

# Getting Started

**Installation**

```
go get github.com/abichinger/fastac
```

First you need to prepare an access control model. The [syntax](https://casbin.org/docs/en/syntax-for-models) of [FastAC models](#supported-models) is identical to Casbin models.

An ACL (Access Control List) model looks like this: 
```ini
#File: model.conf

[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

Next, you need to load some policy rules.
To get started you can load your rules from a text file.
For production you should use a [storage adapter](#adapter-list).
```ini
#File: policy.csv
p, alice, data1, read
p, alice, data2, read
p, bob, data1, write
p, bob, data2, write
```

Go code to resolve access requests
```go
//create an enforcer
e, err := fastac.NewEnforcer("model.conf", "policy.csv")

//check if alice is allowed to read data1
if allow, _ := e.Enforce("alice", "data1", "read"); allow == true {
    // permit alice to read data1
} else {
    // deny the request
}
```


# New Features

## Policy Indexing

[Matchers](https://casbin.org/docs/en/syntax-for-models#matchers) will be divided into multiple stages. As a result FastAC will index all policy rules, which reduces the search space for access requests. This feature brings the most **performance gain**.

## Advanced Policy Filtering

FastAC can filter the policy rules with matchers. The `Filter` function also supports filtering grouping rules.
The fields of a grouping rule can be accessed by `g.user`, `g.role`, `g.domain`

```go
//Examples

//get all policy rules belonging to domain1
e.Filter(SetMatcher("p.dom == \"domain1\"")

//get all policy rules, which grant alice read access
e.Filter(SetMatcher("g(\"alice\", p.sub) && p.act == \"read\"")

//get all grouping rules for alice
e.Filter(SetMatcher("g.user == \"alice\"")
```

# Supported Models

- [ACL](/examples/basic_model.conf) - Access Control List
- [ACL-su](/examples/basic_with_root_model.conf) - Access Control List with super user
- [ABAC](/examples/abac_rule_model.conf) - Attribute Based Access Control
- [RBAC](/examples/rbac_model.conf) - Role Based Access Control
- [RBAC-domain](/examples/rbac_with_domains_model.conf) - Role Based Access Control with domains/tenants

# Adapter List

- File Adapter (built-in) - not recommended for production
- [Gorm Adapter](https://github.com/abichinger/gorm-adapter)

# Performance Comparison

![RBAC Benchmark](./bench/RBAC_op.svg)

![ABAC Benchmark](./bench/ABAC_op.svg)

[More benchmarks](./bench)

# Feature Overview

- [x] Enforcement
- [x] RBAC
- [x] ABAC
- [x] Adapter
- [x] Default Role Manager
- [ ] Third Party Role Managers
- [ ] Filtered Adapter
- [ ] Watcher
- [ ] Dispatcher
