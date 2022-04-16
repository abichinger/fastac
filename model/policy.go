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
	ruleMap map[string]Rule

	*em.Emitter
	*PolicyDef
}

func NewPolicyFromDef(pDef *PolicyDef) *Policy {
	p := &Policy{}
	p.PolicyDef = pDef
	p.Emitter = em.NewEmitter(false)
	p.ruleMap = make(map[string]Rule)
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
	p.ruleMap[hash] = rule
	p.Emitter.EmitEvent(PolicyAdded, rule)
	return true
}

func (p *Policy) RemovePolicy(rule Rule) bool {
	key := rule.Hash()
	_, ok := p.ruleMap[key]
	if !ok {
		return false
	}
	delete(p.ruleMap, key)
	p.Emitter.EmitEvent(PolicyRemoved, rule)
	return true
}

func (p *Policy) Range(fn func(hash string, rule Rule) bool) {
	for hash, r := range p.ruleMap {
		if fn(hash, r) {
			break
		}
	}
}
