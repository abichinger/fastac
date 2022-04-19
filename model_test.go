package fastac

import (
	"testing"

	"example.com/fastac/adapter"
	"example.com/fastac/model"
	"example.com/fastac/model/types"
)

func TestModel(t *testing.T) {
	m, err := model.NewModelFromFile("examples/basic_model.conf")
	if err != nil {
		t.Errorf(err.Error())
	}

	adapter := adapter.NewFileAdapter("examples/basic_policy.csv")
	adapter.LoadPolicy(m)

	err = m.RangeMatchesWithKeys("m", "r", []interface{}{"alice", "data1", "read"}, func(rule types.Rule) bool {
		t.Logf("match: %s", rule.Hash())
		return true
	})
	if err != nil {
		t.Errorf(err.Error())
	}
}
