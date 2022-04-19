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

func (p *Policy) GetDistinct(args []string) ([][]string, error) {
	resMap := make(map[string][]string)
	for i, arg := range args {
		args[i] = p.key + "_" + arg
	}
	for _, rule := range p.ruleMap {
		r, err := p.GetParameters(rule, args)
		if err != nil {
			return nil, err
		}
		resMap[r.Hash()] = r
	}
	res := make([][]string, 0)
	for _, values := range resMap {
		res = append(res, values)
	}
	return res, nil
}

func (p *Policy) Range(fn func(hash string, rule Rule) bool) {
	for hash, r := range p.ruleMap {
		if !fn(hash, r) {
			break
		}
	}
}
