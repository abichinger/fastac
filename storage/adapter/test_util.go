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
	adapter.SavePolicy(save)
	adapter.LoadPolicy(load)

	assert.ElementsMatch(t, util.Join2D(save.rules, ","), util.Join2D(load.rules, ","))
}

func testLoadPolicy(t *testing.T, adapter Adapter, expected [][]string) {
	load := &ModelMock{}
	adapter.LoadPolicy(load)

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
