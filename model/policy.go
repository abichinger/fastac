package model

import (
	"strings"

	em "github.com/vansante/go-event-emitter"
)

const PolicyAdded = "PolicyAdded"
const PolicyRemoved = "PolicyRemoved"

type Rule []string

func (r *Rule) Hash() string {
	return strings.Join(*r, DefaultSep)
}

type Policy struct {
	rules   []Rule
	ruleMap map[string]int

	*em.Emitter
	*PolicyDef
}

func NewPolicyFromDef(pDef *PolicyDef) *Policy {
	p := &Policy{}
	p.PolicyDef = pDef
	p.Emitter = em.NewEmitter(false)
	p.rules = make([]Rule, 0)
	p.ruleMap = make(map[string]int)
	return p
}

func NewPolicy(key, arguments string) *Policy {
	pDef := NewPolicyDef(key, arguments)
	return NewPolicyFromDef(pDef)
}

func (p *Policy) AddPolicy(rule Rule) bool {
	hash := rule.Hash()
	if _, ok := p.ruleMap[hash]; ok {
		return false
	}
	p.ruleMap[hash] = len(p.rules)
	p.rules = append(p.rules, rule)
	p.Emitter.EmitEvent(PolicyAdded, rule)
	return true
}

func (p *Policy) RemovePolicy(rule Rule) bool {
	key := rule.Hash()
	index, ok := p.ruleMap[key]
	if !ok {
		return false
	}
	delete(p.ruleMap, key)
	p.rules = append(p.rules[:index], p.rules[index+1:]...)
	p.Emitter.EmitEvent(PolicyRemoved, rule)
	return true
}

func (p *Policy) Range(fn func(i int, rule Rule) bool) {
	for i, r := range p.rules {
		if fn(i, r) {
			break
		}
	}
}
