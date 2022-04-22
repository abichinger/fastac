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
	"reflect"
	"sort"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/effector"
	e "github.com/abichinger/fastac/model/effector"
	"github.com/abichinger/fastac/model/fm"
	"github.com/abichinger/fastac/model/matcher"
	"github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/model/types"
	"github.com/abichinger/fastac/rbac"
	"github.com/abichinger/fastac/str"
	"github.com/go-ini/ini"
	em "github.com/vansante/go-event-emitter"
)

const (
	RULE_ADDED   = "rule_added"
	RULE_REMOVED = "rule_removed"
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
	NewSectionDef("request_definition", 'r', addRequestDef, removeRequestDef),
	NewSectionDef("policy_definition", 'p', addPolicyDef, removePolicyDef),
	NewSectionDef("role_definition", 'g', addRoleDef, removeRoleDef),
	NewSectionDef("policy_effect", 'e', addEffectDef, removeEffectDef),
	NewSectionDef("matchers", 'm', addMatcherDef, removeMatcherDef),
}

type Model struct {
	pMap    map[string]*policy.Policy
	mDefMap map[string][]*defs.MatcherDef
	mMap    map[string]*matcher.Matcher
	rmMap   map[string]rbac.IRoleManager
	rMap    map[string]*defs.RequestDef
	eMap    map[string]effector.Effector

	secMaps    map[byte]interface{}
	secDefs    map[string]*SectionDef
	secNameMap map[byte]string
	//sec

	fm *fm.FunctionMap
	*em.Emitter
}

func NewModel() *Model {
	m := &Model{}
	m.pMap = make(map[string]*policy.Policy)
	m.mDefMap = make(map[string][]*defs.MatcherDef)
	m.mMap = make(map[string]*matcher.Matcher)
	m.rmMap = make(map[string]rbac.IRoleManager)
	m.rMap = make(map[string]*defs.RequestDef)
	m.eMap = make(map[string]effector.Effector)

	m.secMaps = map[byte]interface{}{
		'r': m.rMap,
		'p': m.pMap,
		'g': m.rmMap,
		'e': m.eMap,
		'm': m.mMap,
	}

	m.secDefs = make(map[string]*SectionDef)
	m.secNameMap = make(map[byte]string)
	m.fm = fm.DefaultFunctionMap()

	for _, sec := range sections {
		m.secDefs[sec.name] = sec
		m.secNameMap[sec.keyPrefix] = sec.name
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

func (m *Model) getSecDefByName(name string) (*SectionDef, bool) {
	sec, ok := m.secDefs[name]
	return sec, ok
}

func (m *Model) getSecDefByKey(key byte) (*SectionDef, bool) {
	name, nameOk := m.secNameMap[key]
	if !nameOk {
		return nil, nameOk
	}
	return m.getSecDefByName(name)
}

func (m *Model) getSecMap(key byte) (map[string]defs.IDef, bool) {
	secMap, ok := m.secMaps[key]
	if !ok {
		return nil, ok
	}

	v := reflect.ValueOf(secMap)
	res := make(map[string]defs.IDef)
	for _, key := range v.MapKeys() {
		value := v.MapIndex(key)
		res[key.String()] = value.Interface().(defs.IDef)
	}

	return res, ok
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
		secDef, ok := m.getSecDefByName(sec.Name())
		if !ok {
			continue
		}

		for _, key := range sec.Keys() {
			if key.Name()[0] != secDef.keyPrefix {
				return fmt.Errorf(str.ERR_INVALID_KEY_PREFIX, secDef.name, secDef.keyPrefix)
			}

			if err := secDef.handler(m, key.Name(), key.String()); err != nil {
				return err
			}
		}
	}

	return m.BuildMatchers()
}

func (m *Model) AddDef(sec byte, key string, value string) error {
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

func addPolicyDef(m *Model, key string, arguments string) error {
	m.pMap[key] = policy.NewPolicy(key, arguments)
	return nil
}

func removePolicyDef(m *Model, key string) error {
	delete(m.pMap, key)
	return nil
}

func addMatcherDef(m *Model, key string, matcher string) error {
	newDef := defs.NewMatcherDef(key, matcher)
	if matcherDefs, ok := m.mDefMap[newDef.GetKey()]; ok {
		for i, def := range matcherDefs {
			if def.GetIndex() > newDef.GetIndex() {
				matcherDefs = append(matcherDefs[0:i+1], matcherDefs[i:]...)
				matcherDefs[i] = newDef
				goto ENDOFLOOP
			}
		}
		matcherDefs = append(matcherDefs, newDef)
	ENDOFLOOP:
		m.mDefMap[newDef.GetKey()] = matcherDefs
	} else {
		m.mDefMap[newDef.GetKey()] = []*defs.MatcherDef{newDef}
	}
	return nil
}

func removeMatcherDef(m *Model, key string) error {
	delete(m.mDefMap, key)
	delete(m.mMap, key)
	return nil
}

func (m *Model) BuildMatchers() error {
	for key := range m.mDefMap {
		if err := m.BuildMatcher(key); err != nil {
			return err
		}
	}
	return nil
}

func (m *Model) BuildMatcher(key string) error {

	defs, ok := m.mDefMap[key]
	if !ok {
		return fmt.Errorf(str.ERR_MATCHER_NOT_FOUND, key)
	}

	pArgs := make([]string, 0)
	for _, def := range defs {
		pArgs = append(pArgs, def.GetPolicyArgs()...)
	}
	pKey := "p"
	if len(pArgs) > 0 {
		pKey = strings.Split(pArgs[0], "_")[0]
	}

	m.mMap[key] = matcher.NewMatcher(m.pMap[pKey], defs)
	return nil
}

func addRoleDef(m *Model, key, arguments string) error {
	def := defs.NewRoleDef(key, arguments)
	if def.NArgs() == 2 {
		m.rmMap[key] = rbac.NewRoleManager(10)
	} else if def.NArgs() == 3 {
		m.rmMap[key] = rbac.NewDomainManager(10)
	}
	m.fm.AddFunction(key, rbac.GenerateGFunction(m.rmMap[key]))
	return nil
}

func removeRoleDef(m *Model, key string) error {
	delete(m.rmMap, key)
	m.fm.RemoveFunction(key)
	return nil
}

func addRequestDef(m *Model, key, arguments string) error {
	m.rMap[key] = defs.NewRequestDef(key, arguments)
	return nil
}

func removeRequestDef(m *Model, key string) error {
	delete(m.rMap, key)
	return nil
}

func addEffectDef(m *Model, key, expr string) error {
	m.eMap[key] = effector.NewDefaultEffector(key, expr)
	return nil
}

func removeEffectDef(m *Model, key string) error {
	delete(m.eMap, key)
	return nil
}

func (m *Model) AddRule(rule []string) (bool, error) {
	key := rule[0]
	sec := key[0]
	switch sec {
	case 'p':
		return m.AddPolicyRule(key, rule[1:])
	case 'g':
		return m.AddRoleRule(key, rule[1:])
	}
	return false, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, key)
}

func (m *Model) RemoveRule(rule []string) (bool, error) {
	key := rule[0]
	sec := key[0]
	switch sec {
	case 'p':
		return m.RemovePolicyRule(key, rule[1:])
	case 'g':
		return m.RemoveRoleRule(key, rule[1:])
	}
	return false, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, key)
}

func (m *Model) AddPolicyRule(key string, rule types.Rule) (bool, error) {
	policy, ok := m.pMap[key]
	if !ok {
		return false, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, key)
	}
	return policy.AddPolicy(rule), nil
}

func (m *Model) RemovePolicyRule(key string, rule types.Rule) (bool, error) {
	policy, ok := m.pMap[key]
	if !ok {
		return false, fmt.Errorf(str.ERR_POLICY_NOT_FOUND, key)
	}
	return policy.RemovePolicy(rule), nil
}

func (m *Model) AddRoleRule(key string, rule types.Rule) (bool, error) {
	rm, ok := m.rmMap[key]
	if !ok {
		return false, fmt.Errorf(str.ERR_RM_NOT_FOUND, key)
	}
	return rm.AddLink(rule[0], rule[1], rule[2:]...)
}
func (m *Model) RemoveRoleRule(key string, rule types.Rule) (bool, error) {
	rm, ok := m.rmMap[key]
	if !ok {
		return false, fmt.Errorf(str.ERR_RM_NOT_FOUND, key)
	}
	return rm.DeleteLink(rule[0], rule[1], rule[2:]...)
}

func (m *Model) GetPolicy(key string) (*policy.Policy, bool) {
	p, ok := m.pMap[key]
	return p, ok
}

func (m *Model) SetPolicy(key string, policy *policy.Policy) {
	panic("not implemented")
}

func (m *Model) GetRoleManager(key string) (rbac.IRoleManager, bool) {
	rm, ok := m.rmMap[key]
	return rm, ok
}

func (m *Model) SetRoleManager(key string, rm rbac.IRoleManager) {
	m.rmMap[key] = rm
	m.fm.AddFunction(key, rbac.GenerateGFunction(rm))
}

func (m *Model) GetMatcher(key string) (*matcher.Matcher, bool) {
	matcher, ok := m.mMap[key]
	return matcher, ok
}

func (m *Model) SetMatcher(key string, matcher *matcher.Matcher) {
	panic("not implemented")
}

func (m *Model) GetRequestDef(key string) (*defs.RequestDef, bool) {
	def, ok := m.rMap[key]
	return def, ok
}

func (m *Model) SetRequestDef(key string, def *defs.RequestDef) {
	panic("not implemented")
}

func (m *Model) GetEffector(key string) (e.Effector, bool) {
	effector, ok := m.eMap[key]
	return effector, ok
}

func (m *Model) SetEffector(key string, eft e.Effector) {
	panic("not implemented")
}

func (m *Model) RangeMatches(matcher *matcher.Matcher, rDef *defs.RequestDef, rvals []interface{}, fn func(rule types.Rule) bool) error {
	return matcher.RangeMatches(*rDef, rvals, *m.fm, fn)
}

func (m *Model) AddFunction(name string, function govaluate.ExpressionFunction) {
	m.fm.AddFunction(name, function)
}

func (m *Model) RemoveFunction(name string) bool {
	return m.fm.RemoveFunction(name)
}

func (m *Model) String() string {
	res := ""
	for _, sec := range sections {
		secMap, ok := m.getSecMap(sec.keyPrefix)
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
			def := secMap[key]
			switch def.(type) {
			case *matcher.Matcher:
				res += secMap[key].String()
			default:
				res += fmt.Sprintf("%s = %s", key, secMap[key].String()) + "\n"
			}

		}

		res += "\n"
	}
	return res
}

func (m *Model) RangeRules(fn func(rule []string) bool) {
	for pKey, p := range m.pMap {
		ruleKey := []string{pKey}
		p.Range(func(hash string, rule types.Rule) bool {
			return fn(append(ruleKey, rule...))
		})
	}
	for gKey, rm := range m.rmMap {
		ruleKey := []string{gKey}
		rm.Range(func(name1, name2 string, domain ...string) bool {
			rule := append(ruleKey, name1)
			rule = append(rule, name2)
			return fn(append(rule, domain...))
		})
	}
}
