package fastac

import (
	"example.com/fastac/adapter"
	"example.com/fastac/model"
)

type Enforcer struct {
	m model.Model
	a adapter.Adapter
}

func NewEnforcer(args ...interface{}) (*Enforcer, error) {
	e := &Enforcer{}

	if len(args) > 0 {
		modelParam := args[0]
		switch modelParam.(type) {
		case string:
			if m, err := model.NewModelFromFile(modelParam.(string)); err != nil {
				return nil, err
			} else {
				e.m = *m
			}
			break
		case model.Model:
			e.m = modelParam.(model.Model)
			break
		}
	}

	if len(args) > 1 {
		adapterParam := args[1]
		switch adapterParam.(type) {
		case string:
			a := adapter.NewFileAdapter(adapterParam.(string))
			if err := a.LoadPolicy(&e.m); err != nil {
				return nil, err
			} else {
				e.a = a
			}
			break
		case adapter.Adapter:
			e.a = adapterParam.(adapter.Adapter)
			break
		}
	}

	return e, nil
}

func (e *Enforcer) AddRule(params ...string) (bool, error) {
	return e.m.AddRule(params)
}

func (e *Enforcer) RemoveRule(params ...string) (bool, error) {
	return e.m.RemoveRule(params)
}

func (e *Enforcer) Enforce(rvals ...interface{}) (bool, error) {
	return e.EnforceWithKeys("m", "r", "e", rvals...)
}

func (e *Enforcer) EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error) {
	return e.EnforceWithMatcherAndKeys(matcher, "r", "e", rvals...)
}

func (e *Enforcer) EnforceWithMatcherAndKeys(matcher string, rKey string, eKey string, rvals ...interface{}) (bool, error) {
	mKey := "m9999"
	e.m.AddDef('m', mKey, matcher)
	e.m.BuildMatcher(mKey)
	defer e.m.RemoveDef('m', mKey)
	return e.EnforceWithKeys(mKey, rKey, eKey, rvals...)
}

func (e *Enforcer) EnforceWithKeys(mKey string, rKey string, eKey string, rvals ...interface{}) (bool, error) {
	return e.m.EnforceWithKeys(mKey, rKey, eKey, rvals)
}

func (e *Enforcer) Filter(rvals ...interface{}) ([]model.Rule, error) {
	return e.FilterWithKeys("m", "r", rvals...)
}

func (e *Enforcer) FilterWithMatcher(matcher string, rvals ...interface{}) ([]model.Rule, error) {
	return e.FilterWithMatcherAndKeys(matcher, "r", rvals...)
}

func (e *Enforcer) FilterWithMatcherAndKeys(matcher string, rKey string, rvals ...interface{}) ([]model.Rule, error) {
	mKey := "m9999"
	e.m.AddDef('m', mKey, matcher)
	e.m.BuildMatcher(mKey)
	defer e.m.RemoveDef('m', mKey)
	return e.FilterWithKeys(mKey, rKey, rvals...)
}

func (e *Enforcer) FilterWithKeys(mKey string, rKey string, rvals ...interface{}) ([]model.Rule, error) {
	rules := []model.Rule{}
	err := e.m.RangeMatchesWithKeys(mKey, rKey, rvals, func(rule model.Rule) bool {
		rules = append(rules, rule)
		return false
	})
	return rules, err
}

func (e *Enforcer) GetModel() *model.Model {
	return &e.m
}
