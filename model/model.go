package model

import (
	"fmt"
	"strings"

	"example.com/lessbin/rbac"
	"github.com/go-ini/ini"
)

type SectionDef struct {
	name      string
	keyPrefix byte
	fn        func(key, value string) error
}

func NewSectionDef(name string, keyPrefix byte, fn func(key, value string) error) *SectionDef {
	sec := &SectionDef{
		name:      name,
		keyPrefix: keyPrefix,
		fn:        fn,
	}
	return sec
}

const invalidKeyPrefix = "error: key of %s must start with '%c'"
const matcherNotFound = "error: matcher %s not found"
const policyNotFound = "error: policy %s not found"
const rmNotFound = "error: role manager %s not found"
const requestNotFound = "error: request definition %s not found"

type Model struct {
	pMap    map[string]*Policy
	mDefMap map[string][]*MatcherDef
	mMap    map[string]*Matcher
	rmMap   map[string]rbac.RoleManager
	rMap    map[string]*ArgsDef
	secDefs map[string]*SectionDef

	fm *FunctionMap
}

func NewModel() *Model {
	m := &Model{}
	m.pMap = make(map[string]*Policy)
	m.mDefMap = make(map[string][]*MatcherDef)
	m.mMap = make(map[string]*Matcher)
	m.rmMap = make(map[string]rbac.RoleManager)
	m.rMap = make(map[string]*ArgsDef)
	m.secDefs = make(map[string]*SectionDef)
	m.fm = DefaultFunctionMap()

	m.secDefs["request_definition"] = NewSectionDef("request_definition", 'r', m.AddRequestDef)
	m.secDefs["policy_definition"] = NewSectionDef("policy_definition", 'p', m.AddPolicyDef)
	//m.secDefs["policy_effect"] = NewSectionDef("policy_effect", 'e', m.AddRequestDef)
	m.secDefs["matchers"] = NewSectionDef("matchers", 'm', m.AddMatcherDef)
	m.secDefs["role_definition"] = NewSectionDef("role_definition", 'g', m.AddRequestDef)

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

			secDef.fn(key.Name(), key.String())
		}
	}

	return m.BuildMatchers()
}

func (m *Model) AddPolicyDef(key string, arguments string) error {
	m.pMap[key] = NewPolicy(key, arguments)
	return nil
}

func (m *Model) AddMatcherDef(key string, matcher string) error {
	newDef := NewMatcherDef(key, matcher)
	if defs, ok := m.mDefMap[newDef.key]; ok {
		for i, def := range defs {
			if def.index > newDef.index {
				defs = append(defs[0:i+1], defs[i:]...)
				defs[i] = newDef
				return nil
			}
		}
		defs = append(defs, newDef)
	} else {
		m.mDefMap[newDef.key] = []*MatcherDef{newDef}
	}
	return nil
}

func (m *Model) BuildMatchers() error {
	for key, _ := range m.mDefMap {
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
	policyKey := strings.Split(pArgs[0], "_")[0]

	m.mMap[key] = NewMatcher(m.pMap[policyKey], defs)
	return nil
}

func (m *Model) AddRoleDef(key, arguments string) error {
	def := NewRoleDef(key, arguments)
	if def.nargs == 2 {
		m.rmMap[key] = rbac.NewRoleManagerImpl(10)
	} else if def.nargs == 3 {
		m.rmMap[key] = rbac.NewDomainManager(10)
	}
	m.fm.AddFunction(key, rbac.GenerateGFunction(m.rmMap[key]))
	return nil
}

func (m *Model) AddRequestDef(key, arguments string) error {
	m.rMap[key] = NewArgsDef(key, arguments)
	return nil
}

func (m *Model) AddPolicyRule(key string, rule Rule) error {
	policy, ok := m.pMap[key]
	if !ok {
		return fmt.Errorf(policyNotFound, key)
	}
	policy.AddPolicy(rule)
	return nil
}

func (m *Model) RemovePolicyRule(key string, rule Rule) (bool, error) {
	policy, ok := m.pMap[key]
	if !ok {
		return false, fmt.Errorf(policyNotFound, key)
	}
	return policy.RemovePolicy(rule), nil
}

func (m *Model) AddRoleRule(key string, rule Rule) error {
	rm, ok := m.rmMap[key]
	if !ok {
		return fmt.Errorf(rmNotFound, key)
	}
	return rm.AddLink(rule[0], rule[1], rule[2:]...)
}
func (m *Model) RemoveRoleRule(key string, rule Rule) error {
	rm, ok := m.rmMap[key]
	if !ok {
		return fmt.Errorf(rmNotFound, key)
	}
	return rm.DeleteLink(rule[0], rule[1], rule[2:]...)
}

func (m *Model) RangeMatches(mKey string, rKey string, rvals []string, fn func(rule Rule) bool) error {
	matcher, mOk := m.mMap[mKey]
	if !mOk {
		return fmt.Errorf(matcherNotFound, mKey)
	}
	rDef, rOk := m.rMap[rKey]
	if !rOk {
		return fmt.Errorf(requestNotFound, rKey)
	}

	return matcher.RangeMatches(*rDef, rvals, *m.fm, fn)
}
