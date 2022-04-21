package fastac

import (
	"fmt"

	"github.com/abichinger/fastac/model"
	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/effector"
	"github.com/abichinger/fastac/model/eft"
	"github.com/abichinger/fastac/model/matcher"
	"github.com/abichinger/fastac/model/types"
	"github.com/abichinger/fastac/storage/adapter"
	"github.com/abichinger/fastac/str"
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
	matcher, mOk := e.m.GetMatcher(mKey)
	if !mOk {
		return false, fmt.Errorf(str.ERR_MATCHER_NOT_FOUND, mKey)
	}
	rDef, rOk := e.m.GetRequestDef(rKey)
	if !rOk {
		return false, fmt.Errorf(str.ERR_REQUESTDEF_NOT_FOUND, rKey)
	}
	effector, eOk := e.m.GetEffector(eKey)
	if !eOk {
		return false, fmt.Errorf(str.ERR_EFFECTOR_NOT_FOUND, eKey)
	}

	return e.enforce(matcher, rDef, effector, rvals)
}

func (e *Enforcer) Filter(rvals ...interface{}) ([]types.Rule, error) {
	return e.FilterWithKeys("m", "r", rvals...)
}

func (e *Enforcer) FilterWithMatcher(matcher string, rvals ...interface{}) ([]types.Rule, error) {
	return e.FilterWithMatcherAndKeys(matcher, "r", rvals...)
}

func (e *Enforcer) FilterWithMatcherAndKeys(matcher string, rKey string, rvals ...interface{}) ([]types.Rule, error) {
	mKey := "m9999"
	e.m.AddDef('m', mKey, matcher)
	e.m.BuildMatcher(mKey)
	defer e.m.RemoveDef('m', mKey)
	return e.FilterWithKeys(mKey, rKey, rvals...)
}

func (e *Enforcer) FilterWithKeys(mKey string, rKey string, rvals ...interface{}) ([]types.Rule, error) {
	rules := []types.Rule{}
	err := e.RangeMatchesWithKeys(mKey, rKey, rvals, func(rule types.Rule) bool {
		rules = append(rules, rule)
		return true
	})
	return rules, err
}

func (e *Enforcer) RangeMatches(matcher *matcher.Matcher, rDef *defs.RequestDef, rvals []interface{}, fn func(rule types.Rule) bool) error {
	return e.m.RangeMatches(matcher, rDef, rvals, fn)
}

func (e *Enforcer) RangeMatchesWithKeys(mKey string, rKey string, rvals []interface{}, fn func(rule types.Rule) bool) error {
	matcher, mOk := e.m.GetMatcher(mKey)
	if !mOk {
		return fmt.Errorf(str.ERR_MATCHER_NOT_FOUND, mKey)
	}
	rDef, rOk := e.m.GetRequestDef(rKey)
	if !rOk {
		return fmt.Errorf(str.ERR_REQUESTDEF_NOT_FOUND, rKey)
	}

	return e.RangeMatches(matcher, rDef, rvals, fn)
}

func (e *Enforcer) enforce(matcher *matcher.Matcher, rDef *defs.RequestDef, effector effector.Effector, rvals []interface{}) (bool, error) {
	pDef := matcher.GetPolicy()
	res := eft.Indeterminate
	effects := []types.Effect{}
	matches := []types.Rule{}

	var eftErr error = nil
	err := e.RangeMatches(matcher, rDef, rvals, func(rule types.Rule) bool {
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

func (e *Enforcer) GetModel() *model.Model {
	return &e.m
}
