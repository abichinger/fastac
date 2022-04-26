package rbac

import (
	"github.com/abichinger/fastac/model/policy"
	em "github.com/vansante/go-event-emitter"
)

type RolePolicy struct {
	rm IRoleManager
	*em.Emitter
}

func NewRolePolicy(rm IRoleManager) *RolePolicy {
	emitter := em.NewEmitter(false)
	return &RolePolicy{rm, emitter}
}

func (p *RolePolicy) AddRule(rule []string) (bool, error) {
	added, err := p.rm.AddLink(rule[0], rule[1], rule[2:]...)
	if !added || err != nil {
		return added, err
	}
	p.Emitter.EmitEvent(policy.EVT_RULE_ADDED, rule)
	return true, nil
}

func (p *RolePolicy) RemoveRule(rule []string) (bool, error) {
	removed, err := p.rm.DeleteLink(rule[0], rule[1], rule[2:]...)
	if !removed || err != nil {
		return removed, err
	}
	p.Emitter.EmitEvent(policy.EVT_RULE_REMOVED, rule)
	return true, nil
}

func (p *RolePolicy) Range(fn func(rule []string) bool) {
	p.rm.Range(func(name1, name2 string, domain ...string) bool {
		rule := []string{name1, name2}
		return fn(append(rule, domain...))
	})
}

func (p *RolePolicy) GetDistinct(columns []int) ([][]string, error) {
	return policy.GetDistinct(p, columns)
}

func (p *RolePolicy) Clear() error {
	return p.rm.Clear()
}

func (p *RolePolicy) GetRoleManager() IRoleManager {
	return p.rm
}
