package matcher

import (
	"testing"

	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/fm"
	"github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/model/types"
)

func TestMatcher(t *testing.T) {

	fm := fm.DefaultFunctionMap()

	p := policy.NewPolicy("p", "sub, obj, act")

	rDef := defs.NewRequestDef("r", "sub, obj, act")

	mDef1 := defs.NewMatcherDef("m.1", "r.sub == p.sub")
	mDef2 := defs.NewMatcherDef("m.2", "r.obj == p.obj && r.act == p.act")
	m1 := NewMatcher(p, []*defs.MatcherDef{mDef1, mDef2})

	m2 := NewMatcher(p, []*defs.MatcherDef{mDef1})

	p.AddPolicy([]string{"alice", "data1", "read"})
	p.AddPolicy([]string{"alice", "data2", "read"})
	p.AddPolicy([]string{"alice", "data1", "write"})
	p.AddPolicy([]string{"alice", "data1", "delete"})
	p.AddPolicy([]string{"bob", "data1", "read"})
	p.AddPolicy([]string{"bob", "data2", "read"})

	t.Logf("M1")
	err := m1.RangeMatches(*rDef, []interface{}{"alice", "data2", "read"}, *fm, func(rule types.Rule) bool {
		t.Logf("match: %s", rule.Hash())
		return true
	})
	if err != nil {
		t.Errorf(err.Error())
	}

	t.Logf("M2")
	err = m2.RangeMatches(*rDef, []interface{}{"alice", "", ""}, *fm, func(rule types.Rule) bool {
		t.Logf("match: %s", rule.Hash())
		return true
	})
	if err != nil {
		t.Errorf(err.Error())
	}
}
