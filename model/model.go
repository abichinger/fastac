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

package model

import (
	"fmt"
	"sort"

	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/effector"
	e "github.com/abichinger/fastac/model/effector"
	"github.com/abichinger/fastac/model/fm"
	"github.com/abichinger/fastac/model/matcher"
	"github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/rbac"
	"github.com/abichinger/fastac/str"
	"github.com/abichinger/govaluate"
	"github.com/go-ini/ini"
	em "github.com/vansante/go-event-emitter"
)

const (
	RULE_ADDED   = "rule_added"
	RULE_REMOVED = "rule_removed"
)

const (
	R_SEC = 'r'
	P_SEC = 'p'
	G_SEC = 'g'
	M_SEC = 'm'
	E_SEC = 'e'
)

type SectionDef struct {
	name          string
	keyPrefix     byte
	handler       func(m *Model, key, value string) error
	removeHandler func(m *Model, key string) error
}

func NewSectionDef(name string, keyPrefix byte, handler func(m *Model, key, value string) error, removeHandler func(m *Model, key string) error) *SectionDef {
	sec := &SectionDef{
		name:          name,
		keyPrefix:     keyPrefix,
		handler:       handler,
		removeHandler: removeHandler,
	}
	return sec
}

var sections = []*SectionDef{
	NewSectionDef("request_definition", R_SEC, addRequestDef, removeRequestDef),
	NewSectionDef("policy_definition", P_SEC, addPolicyDef, removePolicyDef),
	NewSectionDef("role_definition", G_SEC, addRoleDef, removeRoleDef),
	NewSectionDef("policy_effect", E_SEC, addEffectDef, removeEffectDef),
	NewSectionDef("matchers", M_SEC, addMatcherDef, removeMatcherDef),
}

type Model struct {
	defs map[byte]map[string]defs.IDef

	pMap  map[string]policy.IPolicy
	mMap  map[string]matcher.IMatcher
	rpMap map[string]*rbac.RolePolicy
	eMap  map[string]effector.IEffector

	secDefs    map[byte]*SectionDef
	secNameMap map[string]byte

	fm *fm.FunctionMap
	*em.Emitter
}

func NewModel() *Model {
	m := &Model{}
	m.defs = make(map[byte]map[string]defs.IDef)
	m.pMap = make(map[string]policy.IPolicy)
	m.mMap = make(map[string]matcher.IMatcher)
	m.rpMap = make(map[string]*rbac.RolePolicy)
	m.eMap = make(map[string]effector.IEffector)

	m.secDefs = make(map[byte]*SectionDef)
	m.secNameMap = make(map[string]byte)
	m.fm = fm.DefaultFunctionMap()

	for _, sec := range sections {
		m.secDefs[sec.keyPrefix] = sec
		m.secNameMap[sec.name] = sec.keyPrefix
		m.defs[sec.keyPrefix] = make(map[string]defs.IDef)
	}

	m.Emitter = em.NewEmitter(false)

	return m
}

func NewModelFromFile(path string) (*Model, error) {
	m := NewModel()
	if err := m.LoadModel(path); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Model) getSecKeyByName(name string) (byte, bool) {
	sec, ok := m.secNameMap[name]
	return sec, ok
}

func (m *Model) getSecDefByKey(key byte) (*SectionDef, bool) {
	sec, ok := m.secDefs[key]
	return sec, ok
}

// LoadModel loads the model from model CONF file.
func (m *Model) LoadModel(path string) error {
	cfg, err := ini.Load(path)
	if err != nil {
		return err
	}

	return m.loadModelFromConfig(cfg)
}

// LoadModelFromText loads the model from the text.
func (m *Model) LoadModelFromText(text string) error {
	cfg, err := ini.Load([]byte(text))
	if err != nil {
		return err
	}

	return m.loadModelFromConfig(cfg)
}

func (m *Model) loadModelFromConfig(cfg *ini.File) error {
	for _, sec := range cfg.Sections() {
		secKey, ok := m.getSecKeyByName(sec.Name())
		if !ok {
			continue //ignore unknown section
		}

		for _, key := range sec.Keys() {
			err := m.SetDef(secKey, key.Name(), key.String())
			if err != nil {
				return err
			}
		}
	}

	return m.BuildMatchers()
}

func (m *Model) SetDef(sec byte, key string, value string) error {
	secDef, ok := m.getSecDefByKey(sec)
	if !ok {
		return fmt.Errorf(str.ERR_INVALID_SEC, sec)
	}
	if key[0] != secDef.keyPrefix {
		return fmt.Errorf(str.ERR_INVALID_KEY_PREFIX, secDef.name, secDef.keyPrefix)
	}
	if err := secDef.handler(m, key, value); err != nil {
		return err
	}
	return nil
}

func (m *Model) GetDef(sec byte, key string) (defs.IDef, bool) {
	def, ok := m.defs[sec][key]
	return def, ok
}

func (m *Model) RemoveDef(sec byte, key string) error {
	secDef, ok := m.getSecDefByKey(sec)
	if !ok {
		return fmt.Errorf(str.ERR_INVALID_SEC, sec)
	}
	if err := secDef.removeHandler(m, key); err != nil {
		return err
	}
	return nil
}

func (m *Model) BuildMatchers() error {
	for key := range m.defs[M_SEC] {
		if err := m.BuildMatcher(key); err != nil {
			return err
		}
	}
	return nil
}

func (m *Model) BuildMatcher(key string) error {

	def, ok := m.defs[M_SEC][key]
	if !ok {
		return fmt.Errorf(str.ERR_MATCHER_NOT_FOUND, key)
	}
	mDef := def.(*defs.MatcherDef)
	matcher, err := m.BuildMatcherFromDef(mDef)
	if err != nil {
		return err
	}
	m.mMap[key] = matcher
	return nil
}

func (m *Model) BuildMatcherFromDef(mDef *defs.MatcherDef) (matcher.IMatcher, error) {
	if err := mDef.Build(m.fm.GetFunctions()); err != nil {
		return nil, err
	}

	pKey := mDef.GetPolicyKey()
	var pDef *defs.PolicyDef
	switch pKey[0] {
	case P_SEC:
		def, ok := m.defs[P_SEC][pKey]
		if !ok {
			return nil, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, pKey)
		}
		pDef = def.(*defs.PolicyDef)
	case G_SEC:
		pDef = defs.NewPolicyDef(pKey, "user, role, domain")
	default:
		return nil, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, pKey)
	}

	policy, ok := m.GetPolicy(pKey)
	if !ok {
		return nil, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, pKey)
	}

	return matcher.NewMatcher(pDef, policy, mDef.Root()), nil
}

func (m *Model) AddRule(rule []string) (bool, error) {
	key := rule[0]
	sec := key[0]
	switch sec {
	case 'p':
		return m.addPolicyRule(key, rule[1:])
	case 'g':
		return m.addRoleRule(key, rule[1:])
	}
	return false, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, key)
}

func (m *Model) RemoveRule(rule []string) (bool, error) {
	key := rule[0]
	sec := key[0]
	switch sec {
	case 'p':
		return m.removePolicyRule(key, rule[1:])
	case 'g':
		return m.removeRoleRule(key, rule[1:])
	}
	return false, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, key)
}

func (m *Model) addPolicyRule(key string, rule []string) (bool, error) {
	policy, ok := m.pMap[key]
	if !ok {
		return false, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, key)
	}
	return policy.AddRule(rule)
}

func (m *Model) removePolicyRule(key string, rule []string) (bool, error) {
	policy, ok := m.pMap[key]
	if !ok {
		return false, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, key)
	}
	return policy.RemoveRule(rule)
}

func (m *Model) addRoleRule(key string, rule []string) (bool, error) {
	rp, ok := m.rpMap[key]
	if !ok {
		return false, fmt.Errorf(str.ERR_RM_NOT_FOUND, key)
	}
	return rp.AddRule(rule)
}
func (m *Model) removeRoleRule(key string, rule []string) (bool, error) {
	rp, ok := m.rpMap[key]
	if !ok {
		return false, fmt.Errorf(str.ERR_RM_NOT_FOUND, key)
	}
	return rp.RemoveRule(rule)
}

func (m *Model) GetPolicy(key string) (policy.IPolicy, bool) {
	p, ok := m.pMap[key]
	if !ok {
		p, ok = m.rpMap[key]
	}
	return p, ok
}

func (m *Model) SetPolicy(key string, policy policy.IPolicy) {
	m.pMap[key] = policy
}

func (m *Model) GetRoleManager(key string) (rbac.IRoleManager, bool) {
	rp, ok := m.rpMap[key]
	return rp.GetRoleManager(), ok
}

func (m *Model) SetRoleManager(key string, rm rbac.IRoleManager) {
	m.rpMap[key] = rbac.NewRolePolicy(rm)
	m.fm.SetFunction(key, rbac.GenerateGFunction(rm))
}

func (m *Model) GetMatcher(key string) (matcher.IMatcher, bool) {
	matcher, ok := m.mMap[key]
	return matcher, ok
}

func (m *Model) SetMatcher(key string, matcher matcher.IMatcher) {
	m.mMap[key] = matcher
}

func (m *Model) GetRequestDef(key string) (*defs.RequestDef, bool) {
	def, ok := m.defs[R_SEC][key]
	return def.(*defs.RequestDef), ok
}

func (m *Model) SetRequestDef(key string, def *defs.RequestDef) {
	m.defs[R_SEC][key] = def
}

func (m *Model) GetEffector(key string) (e.IEffector, bool) {
	effector, ok := m.eMap[key]
	return effector, ok
}

func (m *Model) SetEffector(key string, effector e.IEffector) {
	m.eMap[key] = effector
}

func (m *Model) RangeMatches(matcher matcher.IMatcher, rDef *defs.RequestDef, rvals []interface{}, fn func(rule []string) bool) error {
	policyKey := []string{matcher.GetPolicyKey()}
	return matcher.RangeMatches(*rDef, rvals, *m.fm, func(rule []string) bool {
		return fn(append(policyKey, rule...))
	})
}

func (m *Model) SetFunction(name string, function govaluate.ExpressionFunction) {
	m.fm.SetFunction(name, function)
}

func (m *Model) RemoveFunction(name string) bool {
	return m.fm.RemoveFunction(name)
}

func (m *Model) String() string {
	res := ""
	for _, sec := range sections {
		secMap, ok := m.defs[sec.keyPrefix]
		if !ok || len(secMap) == 0 {
			continue
		}
		res += fmt.Sprintf("[%s]\n", sec.name)

		keys := []string{}
		for key := range secMap {
			keys = append(keys, key)
		}

		sort.Strings(keys)

		for _, key := range keys {
			res += secMap[key].String() + "\n"
		}

		res += "\n"
	}
	return res
}

func (m *Model) RangeRules(fn func(rule []string) bool) {
	for pKey, p := range m.pMap {
		ruleKey := []string{pKey}
		p.Range(func(rule []string) bool {
			return fn(append(ruleKey, rule...))
		})
	}
	for gKey, rm := range m.rpMap {
		ruleKey := []string{gKey}
		rm.Range(func(rule []string) bool {
			return fn(append(ruleKey, rule...))
		})
	}
}

func (m *Model) ClearPolicy(pKey string) error {
	p, ok := m.GetPolicy(pKey)
	if !ok {
		return fmt.Errorf(str.ERR_POLICY_NOT_FOUND, pKey)
	}
	return p.Clear()
}
