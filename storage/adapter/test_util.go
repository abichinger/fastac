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

package adapter

import (
	"testing"

	"github.com/abichinger/fastac/util"
	"github.com/stretchr/testify/assert"
)

type ModelMock struct {
	rules [][]string
}

func (m *ModelMock) AddRule(rule []string) (bool, error) {
	m.rules = append(m.rules, rule)
	return true, nil
}

func (m *ModelMock) RangeRules(fn func(rule []string) bool) {
	for _, rule := range m.rules {
		if !fn(rule) {
			break
		}
	}
}

func testSavePolicy(t *testing.T, adapter Adapter, rules [][]string) {
	save := &ModelMock{rules}
	load := &ModelMock{}
	if err := adapter.SavePolicy(save); err != nil {
		t.Error(err.Error())
	}
	if err := adapter.LoadPolicy(load); err != nil {
		t.Error(err.Error())
	}

	assert.ElementsMatch(t, util.Join2D(save.rules, ","), util.Join2D(load.rules, ","))
}

func testLoadPolicy(t *testing.T, adapter Adapter, expected [][]string) {
	load := &ModelMock{}
	if err := adapter.LoadPolicy(load); err != nil {
		t.Error(err.Error())
	}

	assert.ElementsMatch(t, util.Join2D(expected, ","), util.Join2D(load.rules, ","))
}

func BasicAdapterTest(t *testing.T, adapter Adapter) {

	rules := [][]string{
		{"p", "group1", "data1", "read"},
		{"p", "alice", "data2", "read"},
		{"g", "alice", "group1"},
	}

	modified_rules := [][]string{
		{"p", "group1", "data1", "read"},
		{"p", "bob", "data2", "read"},
		{"g", "bob", "group1"},
	}

	unknown_rule := []string{"p", "john", "data1", "read"}

	testSavePolicy(t, adapter, rules)
	testLoadPolicy(t, adapter, rules)

	switch adapter.(type) {
	case SimpleAdapter:
		sa := adapter.(SimpleAdapter)
		sa.AddRule(modified_rules[1])
		sa.AddRule(modified_rules[2])

		sa.RemoveRule(rules[1])
		sa.RemoveRule(rules[2])

		testLoadPolicy(t, sa, modified_rules)

		sa.AddRule(modified_rules[0])
		sa.RemoveRule(unknown_rule)

		testLoadPolicy(t, sa, modified_rules)
	}

	testSavePolicy(t, adapter, rules)

	switch adapter.(type) {
	case BatchAdapter:
		sa := adapter.(BatchAdapter)
		sa.AddRules([][]string{modified_rules[1], modified_rules[2]})
		sa.RemoveRules([][]string{rules[1], rules[2]})

		testLoadPolicy(t, sa, modified_rules)

		sa.AddRules([][]string{modified_rules[0]})
		sa.RemoveRules([][]string{unknown_rule})

		testLoadPolicy(t, sa, modified_rules)
	}
}
