package policy

import (
	"testing"

	"example.com/fastac/util"
	"github.com/stretchr/testify/assert"
)

func loadTestPolicy(p *Policy, rules [][]string) {
	for _, rule := range rules {
		p.AddPolicy(rule)
	}
}

func TestGetDistinct(t *testing.T) {
	p := NewPolicy("p", "sub, obj, act")
	rules := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	}

	loadTestPolicy(p, rules)

	subjects, _ := p.GetDistinct([]string{"sub"})
	objects, _ := p.GetDistinct([]string{"obj"})
	actions, _ := p.GetDistinct([]string{"act"})
	assert.ElementsMatch(t, util.Join2D(subjects, ""), []string{"alice", "bob", "data2_admin"})
	assert.ElementsMatch(t, util.Join2D(objects, ""), []string{"data1", "data2"})
	assert.ElementsMatch(t, util.Join2D(actions, ""), []string{"read", "write"})
}
