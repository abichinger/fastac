// Copyright 2022 The FastAC Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fastac

import (
	"fmt"
	"testing"

	casbin "github.com/casbin/casbin/v2"
	"github.com/stretchr/testify/assert"
)

type RulesAPI interface {
	AddPolicy(params ...interface{}) (bool, error)
	AddGroupingPolicy(params ...interface{}) (bool, error)

	RemovePolicy(params ...interface{}) (bool, error)
	RemoveGroupingPolicy(params ...interface{}) (bool, error)

	Enforce(rvals ...interface{}) (bool, error)
}

type RulesAPICasbinEnforcer struct {
	*casbin.Enforcer
}

func NewRulesAPICasbinEnforcer(model string) RulesAPI {
	e := RulesAPICasbinEnforcer{}
	enforcer, err := casbin.NewEnforcer(model, false)
	if err != nil {
		panic(err)
	}
	e.Enforcer = enforcer
	return &e
}

func (e *RulesAPICasbinEnforcer) AddPolicy(params ...interface{}) (bool, error) {
	return e.Enforcer.AddPolicy(params...)
}
func (e *RulesAPICasbinEnforcer) AddGroupingPolicy(params ...interface{}) (bool, error) {
	return e.Enforcer.AddGroupingPolicy(params...)
}
func (e *RulesAPICasbinEnforcer) RemovePolicy(params ...interface{}) (bool, error) {
	return e.Enforcer.RemovePolicy(params...)
}
func (e *RulesAPICasbinEnforcer) RemoveGroupingPolicy(params ...interface{}) (bool, error) {
	return e.Enforcer.RemoveGroupingPolicy(params...)
}

type RulesAPIEnforcer struct {
	*Enforcer
}

func NewRulesAPIEnforcer(model string) RulesAPI {
	e := RulesAPIEnforcer{}
	enforcer, err := NewEnforcer(model, nil, nil)
	if err != nil {
		panic(err)
	}
	e.Enforcer = enforcer
	return &e
}

func (e *RulesAPIEnforcer) GeParams(key string, params ...interface{}) []string {
	res := []string{key}
	for _, p := range params {
		res = append(res, p.(string))
	}
	return res
}

func (e *RulesAPIEnforcer) AddPolicy(params ...interface{}) (bool, error) {
	return e.AddRule(e.GeParams("p", params...))
}
func (e *RulesAPIEnforcer) AddGroupingPolicy(params ...interface{}) (bool, error) {
	return e.AddRule(e.GeParams("g", params...))
}
func (e *RulesAPIEnforcer) RemovePolicy(params ...interface{}) (bool, error) {
	return e.RemoveRule(e.GeParams("p", params...))
}
func (e *RulesAPIEnforcer) RemoveGroupingPolicy(params ...interface{}) (bool, error) {
	return e.RemoveRule(e.GeParams("g", params...))
}
func (e *RulesAPIEnforcer) Enforce(params ...interface{}) (bool, error) {
	return e.Enforcer.Enforce(params)
}

func genRBACPolicy(e RulesAPI, n int) error {
	for i := 0; i < n; i++ {
		_, err := e.AddGroupingPolicy(fmt.Sprintf("user%d", i), fmt.Sprintf("group%d", i/10))
		if err != nil {
			return err
		}
	}

	for i := 0; i < n/10; i++ {
		_, err := e.AddPolicy(fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "read")
		if err != nil {
			return err
		}
	}
	return nil
}

func genABACPolicy(e RulesAPI, n int) error {
	for i := 0; i < n; i++ {
		_, err := e.AddPolicy(fmt.Sprintf("r.sub.Age > %d", i%100), fmt.Sprintf("data%d", i), "read")
		if err != nil {
			return err
		}
	}
	return nil
}

func TestRBACBenchmarkPolicy(t *testing.T) {
	e := NewRulesAPIEnforcer("examples/rbac_model.conf")
	if err := genRBACPolicy(e, 1000); err != nil {
		t.Fatal()
	}

	testEnforce := func(t *testing.T, e RulesAPI, expected bool, params ...interface{}) {
		actual, _ := e.Enforce(params...)
		assert.Equal(t, expected, actual)
	}

	testEnforce(t, e, false, "user501", "data9", "read")
	testEnforce(t, e, true, "user501", "data5", "read")

	e = NewRulesAPIEnforcer("examples/rbac_model_index.conf")
	if err := genRBACPolicy(e, 1000); err != nil {
		t.Fatal()
	}
	testEnforce(t, e, false, "user501", "data9", "read")
	testEnforce(t, e, true, "user501", "data5", "read")
}

func BenchmarkRBAC(b *testing.B) {
	benchmarks := []struct {
		name string
		size int
	}{
		{name: "Large", size: 100000},
		{name: "Medium", size: 10000},
		{name: "Small", size: 1000},
	}

	enforcers := []struct {
		name  string
		model string
		init  func(model string) RulesAPI
	}{
		{name: "Casbin", model: "examples/rbac_model.conf", init: NewRulesAPICasbinEnforcer},
		{name: "FastAC", model: "examples/rbac_model.conf", init: NewRulesAPIEnforcer},
		{name: "FastAC-index", model: "examples/rbac_model_index.conf", init: NewRulesAPIEnforcer},
	}

	for _, bm := range benchmarks {
		b.Run(fmt.Sprintf("size=%s(%d)", bm.name, bm.size), func(b *testing.B) {
			for _, e := range enforcers {
				b.Run("enforcer="+e.name, func(b *testing.B) {
					enf := e.init(e.model)

					if err := genRBACPolicy(enf, bm.size); err != nil {
						b.Fatal()
					}

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = enf.Enforce("user501", "data9", "read")
					}
				})
			}
		})
	}
}

func BenchmarkAddPolicy(b *testing.B) {
	benchmarks := []struct {
		name string
		size int
	}{
		{name: "Large", size: 10000},
		{name: "Medium", size: 1000},
		{name: "Empty", size: 0},
	}

	enforcers := []struct {
		name  string
		model string
		init  func(model string) RulesAPI
	}{
		{name: "Casbin", model: "examples/rbac_model.conf", init: NewRulesAPICasbinEnforcer},
		{name: "FastAC", model: "examples/rbac_model.conf", init: NewRulesAPIEnforcer},
		{name: "FastAC-index", model: "examples/rbac_model_index.conf", init: NewRulesAPIEnforcer},
	}

	for _, bm := range benchmarks {
		b.Run(fmt.Sprintf("size=%s(%d)", bm.name, bm.size), func(b *testing.B) {
			for _, e := range enforcers {
				b.Run("enforcer="+e.name, func(b *testing.B) {
					enf := e.init(e.model)

					if err := genRBACPolicy(enf, bm.size*10); err != nil {
						b.Fatal()
					}

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = enf.AddPolicy(fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "write")
					}
				})
			}
		})
	}
}

func BenchmarkRemovePolicy(b *testing.B) {
	benchmarks := []struct {
		name string
		size int
	}{
		{name: "Large", size: 1000},
		{name: "Medium", size: 100},
		{name: "Empty", size: 0},
	}

	enforcers := []struct {
		name  string
		model string
		init  func(model string) RulesAPI
	}{
		{name: "Casbin", model: "examples/rbac_model.conf", init: NewRulesAPICasbinEnforcer},
		{name: "FastAC", model: "examples/rbac_model.conf", init: NewRulesAPIEnforcer},
		{name: "FastAC-index", model: "examples/rbac_model_index.conf", init: NewRulesAPIEnforcer},
	}

	for _, bm := range benchmarks {
		b.Run(fmt.Sprintf("size=%s(%d)", bm.name, bm.size), func(b *testing.B) {
			for _, e := range enforcers {
				b.Run("enforcer="+e.name, func(b *testing.B) {
					enf := e.init(e.model)

					if err := genRBACPolicy(enf, bm.size*10); err != nil {
						b.Fatal()
					}

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = enf.RemovePolicy(fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "read")
					}
				})
			}
		})
	}
}

func BenchmarkABAC(b *testing.B) {

	benchmarks := []struct {
		name string
		size int
	}{
		{name: "Large", size: 1000},
		{name: "Medium", size: 100},
		{name: "Small", size: 10},
	}

	sub := struct {
		Age int
	}{
		Age: 16,
	}

	enforcers := []struct {
		name  string
		model string
		init  func(model string) RulesAPI
	}{
		{name: "Casbin", model: "examples/abac_rule_model.conf", init: NewRulesAPICasbinEnforcer},
		{name: "FastAC", model: "examples/abac_rule_model.conf", init: NewRulesAPIEnforcer},
		{name: "FastAC-index", model: "examples/abac_rule_model_index.conf", init: NewRulesAPIEnforcer},
	}

	for _, bm := range benchmarks {
		b.Run(fmt.Sprintf("size=%s(%d)", bm.name, bm.size), func(b *testing.B) {
			for _, e := range enforcers {
				b.Run("enforcer="+e.name, func(b *testing.B) {
					enf := e.init(e.model)

					if err := genABACPolicy(enf, bm.size); err != nil {
						b.Fatal()
					}

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = enf.Enforce(sub, "data50", "read")
					}
				})
			}
		})
	}
}
