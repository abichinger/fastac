package model

import (
	"fmt"
	"strings"

	"example.com/fastac/model/defs"
	"example.com/fastac/model/effector"
	"example.com/fastac/model/eft"
	"example.com/fastac/model/fm"
	"example.com/fastac/model/matcher"
	"example.com/fastac/model/policy"
	"example.com/fastac/model/types"
	"example.com/fastac/rbac"
	"github.com/Knetic/govaluate"
	"github.com/go-ini/ini"
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
	NewSectionDef("policy_effect", 'e', addEffectDef, removeEffectDef),
	NewSectionDef("matchers", 'm', addMatcherDef, removeMatcherDef),
	NewSectionDef("role_definition", 'g', addRoleDef, removeRoleDef),
}

const invalidSec = "error: invalid sec %c"
const invalidKeyPrefix = "error: key of %s must start with '%c'"
const matcherNotFound = "error: matcher %s not found"
const policyNotFound = "error: policy %s not found"
const rmNotFound = "error: role manager %s not found"
const requestNotFound = "error: request definition %s not found"
const effectNotFound = "error: effect definition %s not found"

type Model struct {
	pMap    map[string]*policy.Policy
	mDefMap map[string][]*defs.MatcherDef
	mMap    map[string]*matcher.Matcher
	rmMap   map[string]rbac.IRoleManager
	rMap    map[string]*defs.RequestDef
	secDefs map[string]*SectionDef
	secMap  map[byte]*SectionDef
	eMap    map[string]effector.Effector

	fm *fm.FunctionMap
}

func NewModel() *Model {
	m := &Model{}
	m.pMap = make(map[string]*policy.Policy)
	m.mDefMap = make(map[string][]*defs.MatcherDef)
	m.mMap = make(map[string]*matcher.Matcher)
	m.rmMap = make(map[string]rbac.IRoleManager)
	m.rMap = make(map[string]*defs.RequestDef)
	m.secDefs = make(map[string]*SectionDef)
	m.secMap = make(map[byte]*SectionDef)
	m.eMap = make(map[string]effector.Effector)
	m.fm = fm.DefaultFunctionMap()

	for _, sec := range sections {
		m.secDefs[sec.name] = sec
		m.secMap[sec.keyPrefix] = sec
	}

	return m
}

func NewModelFromFile(path string) (*Model, error) {
	m := NewModel()
	if err := m.LoadModel(path); err != nil {
		return nil, err
	}
	return m, nil
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
		secDef, ok := m.secDefs[sec.Name()]
		if !ok {
			continue
		}

		for _, key := range sec.Keys() {
			if key.Name()[0] != secDef.keyPrefix {
				return fmt.Errorf(invalidKeyPrefix, secDef.name, secDef.keyPrefix)
			}

			secDef.handler(m, key.Name(), key.String())
		}
	}

	return m.BuildMatchers()
}

func (m *Model) AddDef(sec byte, key string, value string) error {
	secDef, ok := m.secMap[sec]
	if !ok {
		return fmt.Errorf(invalidSec, sec)
	}
	if key[0] != secDef.keyPrefix {
		return fmt.Errorf(invalidKeyPrefix, secDef.name, secDef.keyPrefix)
	}
	if err := secDef.handler(m, key, value); err != nil {
		return err
	}
	return nil
}

func (m *Model) RemoveDef(sec byte, key string) error {
	secDef, ok := m.secMap[sec]
	if !ok {
		return fmt.Errorf(invalidSec, sec)
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
		return fmt.Errorf(matcherNotFound, key)
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
	return false, fmt.Errorf(policyNotFound, key)
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
	return false, fmt.Errorf(policyNotFound, key)
}

func (m *Model) AddPolicyRule(key string, rule types.Rule) (bool, error) {
	policy, ok := m.pMap[key]
	if !ok {
		return false, fmt.Errorf(policyNotFound, key)
	}
	return policy.AddPolicy(rule), nil
}

func (m *Model) RemovePolicyRule(key string, rule types.Rule) (bool, error) {
	policy, ok := m.pMap[key]
	if !ok {
		return false, fmt.Errorf(policyNotFound, key)
	}
	return policy.RemovePolicy(rule), nil
}

func (m *Model) AddRoleRule(key string, rule types.Rule) (bool, error) {
	rm, ok := m.rmMap[key]
	if !ok {
		return false, fmt.Errorf(rmNotFound, key)
	}
	return rm.AddLink(rule[0], rule[1], rule[2:]...)
}
func (m *Model) RemoveRoleRule(key string, rule types.Rule) (bool, error) {
	rm, ok := m.rmMap[key]
	if !ok {
		return false, fmt.Errorf(rmNotFound, key)
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

func (m *Model) RangeMatches(matcher *matcher.Matcher, rDef *defs.RequestDef, rvals []interface{}, fn func(rule types.Rule) bool) error {
	return matcher.RangeMatches(*rDef, rvals, *m.fm, fn)
}

func (m *Model) RangeMatchesWithKeys(mKey string, rKey string, rvals []interface{}, fn func(rule types.Rule) bool) error {
	matcher, mOk := m.mMap[mKey]
	if !mOk {
		return fmt.Errorf(matcherNotFound, mKey)
	}
	rDef, rOk := m.rMap[rKey]
	if !rOk {
		return fmt.Errorf(requestNotFound, rKey)
	}

	return m.RangeMatches(matcher, rDef, rvals, fn)
}

func (m *Model) Enforce(matcher *matcher.Matcher, rDef *defs.RequestDef, effector effector.Effector, rvals []interface{}) (bool, error) {
	pDef := matcher.GetPolicy()
	res := eft.Indeterminate
	effects := []types.Effect{}
	matches := []types.Rule{}

	var eftErr error = nil
	err := m.RangeMatches(matcher, rDef, rvals, func(rule types.Rule) bool {
		effect := pDef.GetEft(rule)

		effects = append(effects, effect)
		matches = append(matches, rule)

		res, _, eftErr = effector.MergeEffects(effects, matches, false)

		if eftErr != nil || res != eft.Indeterminate {
			return false
		}
		return true
	})
	if err != nil {
		return false, err
	}
	if eftErr != nil {
		return false, err
	}

	if res == eft.Indeterminate {
		res, _, _ = effector.MergeEffects(effects, matches, true)
	}

	return res == eft.Allow, nil
}

func (m *Model) EnforceWithKeys(mKey string, rKey string, eKey string, rvals []interface{}) (bool, error) {
	matcher, mOk := m.mMap[mKey]
	if !mOk {
		return false, fmt.Errorf(matcherNotFound, mKey)
	}
	rDef, rOk := m.rMap[rKey]
	if !rOk {
		return false, fmt.Errorf(requestNotFound, rKey)
	}
	effector, eOk := m.eMap[eKey]
	if !eOk {
		return false, fmt.Errorf(effectNotFound, eKey)
	}

	return m.Enforce(matcher, rDef, effector, rvals)
}

func (m *Model) AddFunction(name string, function govaluate.ExpressionFunction) {
	m.fm.AddFunction(name, function)
}
