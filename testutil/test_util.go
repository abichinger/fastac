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

package testutil

import (
	"testing"

	"github.com/abichinger/fastac/storage"
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

func testSavePolicy(t *testing.T, adapter storage.Adapter, rules [][]string) {
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

func testLoadPolicy(t *testing.T, adapter storage.Adapter, expected [][]string) {
	load := &ModelMock{}
	if err := adapter.LoadPolicy(load); err != nil {
		t.Error(err.Error())
	}

	assert.ElementsMatch(t, util.Join2D(expected, ","), util.Join2D(load.rules, ","))
}

func testAddRule(t *testing.T, adapter storage.SimpleAdapter, rule []string) {
	t.Helper()
	if err := adapter.AddRule(rule); err != nil {
		t.Error(err.Error())
	}
}

func testRemoveRule(t *testing.T, adapter storage.SimpleAdapter, rule []string) {
	t.Helper()
	if err := adapter.RemoveRule(rule); err != nil {
		t.Error(err.Error())
	}
}

func testAddRules(t *testing.T, adapter storage.BatchAdapter, rules [][]string) {
	t.Helper()
	if err := adapter.AddRules(rules); err != nil {
		t.Error(err.Error())
	}
}

func testRemoveRules(t *testing.T, adapter storage.BatchAdapter, rules [][]string) {
	t.Helper()
	if err := adapter.RemoveRules(rules); err != nil {
		t.Error(err.Error())
	}
}

func BasicAdapterTest(t *testing.T, adapter storage.Adapter) {

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

	switch a := adapter.(type) {
	case storage.SimpleAdapter:
		testAddRule(t, a, modified_rules[1])
		testAddRule(t, a, modified_rules[2])

		testRemoveRule(t, a, rules[1])
		testRemoveRule(t, a, rules[2])

		testLoadPolicy(t, a, modified_rules)

		testRemoveRule(t, a, unknown_rule)
		testLoadPolicy(t, a, modified_rules)
	}

	testSavePolicy(t, adapter, rules)

	switch a := adapter.(type) {
	case storage.BatchAdapter:
		testAddRules(t, a, [][]string{modified_rules[1], modified_rules[2]})
		testRemoveRules(t, a, [][]string{rules[1], rules[2]})

		testLoadPolicy(t, a, modified_rules)

		testRemoveRules(t, a, [][]string{unknown_rule})
		testLoadPolicy(t, a, modified_rules)
	}
}
