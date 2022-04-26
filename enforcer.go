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

package fastac

import (
	"errors"

	"github.com/abichinger/fastac/model"
	m "github.com/abichinger/fastac/model"
	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/eft"
	"github.com/abichinger/fastac/model/types"
	"github.com/abichinger/fastac/storage"
	a "github.com/abichinger/fastac/storage/adapter"
	"github.com/abichinger/fastac/str"
)

type Enforcer struct {
	model   *m.Model
	adapter a.Adapter
	sc      *storage.StorageController
}

type Option func(*Enforcer) error

// Option to disable/enable the autosave feature (default: disabled)
// If autosave is disabled, Flush needs to be called to save modified rules
// Enable autosave:
// 	NewEnforcer(model, adapter, OptionAutosave(true))
// Or:
// 	e.SetOption(OptionAutosave(true))
func OptionAutosave(autosave bool) Option {
	return func(e *Enforcer) error {
		if autosave {
			e.sc.EnableAutosave()
		} else {
			e.sc.DisableAutosave()
		}
		return nil
	}
}

// Option to disable/enable the storage feature (default: enabled, if an adapter is supplied)
// If storage is disabled, the StorageController will not listen for rule updates
func OptionStorage(enable bool) Option {
	return func(e *Enforcer) error {
		if enable {
			e.sc.Enable()
		} else {
			e.sc.Disable()
		}
		return nil
	}
}

// NewEnforcer creates a new Enforcer instance. An Enforcer is the main item of FastAC
//
// Without adapter and default options:
//
//  NewEnforcer("model.conf", nil)
//
// With adapter and autosave enabled
//
//  adapter := gormadapter.NewAdapter(db, tableName)
//  NewEnforcer("model.conf", adapter, OptionAutosave(true))
func NewEnforcer(model interface{}, adapter interface{}, options ...Option) (*Enforcer, error) {
	e := &Enforcer{}

	switch m2 := model.(type) {
	case string:
		if m, err := m.NewModelFromFile(model.(string)); err != nil {
			return nil, err
		} else {
			e.model = m
		}
	case m.Model:
		e.model = &m2
	case *m.Model:
		e.model = m2
	default:
		return nil, errors.New(str.ERR_INVALID_MODEL)
	}

	var a3 a.Adapter
	switch a2 := adapter.(type) {
	case string:
		a3 := a.NewFileAdapter(a2)
		if err := a3.LoadPolicy(e.model); err != nil {
			return nil, err
		}
	case a.Adapter:
		a3 = a2
	default:
		a3 = &a.NoopAdapter{}
		options = append(options, OptionStorage(false))
	}

	e.SetAdapter(a3)

	for _, option := range options {
		if err := option(e); err != nil {
			return nil, err
		}
	}

	return e, nil
}

// SetOption applies an option to the Enforcer
func (e *Enforcer) SetOption(option Option) error {
	return option(e)
}

// SetAdapter sets the storage adapter
func (e *Enforcer) SetAdapter(adapter a.Adapter) {
	autosave := false
	if e.sc != nil {
		autosave = e.sc.AutosaveEnabled()
		e.sc.Disable()
	}
	e.sc = storage.NewStorageController(e.model, adapter, autosave)
	e.adapter = adapter
}

// LoadPolicy loads all rules from the storage adapter into the model.
// The model is not cleared before the loading process
func (e *Enforcer) LoadPolicy() error {
	if e.sc.Enabled() {
		e.sc.Disable()
		defer e.sc.Enable()
	}
	return e.adapter.LoadPolicy(e.model)
}

//SavePolicy stores all rules from the model into the storage adapter.
func (e *Enforcer) SavePolicy() error {
	return e.adapter.SavePolicy(e.model)
}

// Flush sends all the modifications of the rule set to the storage adapter.
//
// store rule, when autosave is disabled:
//  e.AddRule("g", "alice", "group1")
//  e.Flush()
func (e *Enforcer) Flush() error {
	return e.sc.Flush()
}

// AddRule adds a rule to the model
// Returns false, if the rule was already present
//
// Add policy rule:
//  e.AddRule("p", "alice", "data1", "read")
// Add grouping rule:
//  e.AddRule("g", "alice", "group1")
func (e *Enforcer) AddRule(rule []string) (bool, error) {
	return e.model.AddRule(rule)
}

// RemoveRule removes a rule from the model
// Returns false, if the rule was not present
//
// Add policy rule:
//  e.RemoveRule("p", "alice", "data1", "read")
// Add grouping rule:
//  e.RemoveRule("g", "alice", "group1")
func (e *Enforcer) RemoveRule(rule []string) (bool, error) {
	return e.model.RemoveRule(rule)
}

// AddRules adds multiple rules to the model
func (e *Enforcer) AddRules(rules [][]string) error {
	if e.sc.AutosaveEnabled() {
		e.sc.DisableAutosave()
		defer func() {
			e.sc.EnableAutosave()
			if err := e.sc.Flush(); err != nil {
				panic(err)
			}
		}()
	}
	for _, rule := range rules {
		if _, err := e.model.AddRule(rule); err != nil {
			return err
		}
	}
	return nil
}

// RemoveRules removes multiple rules from the model
func (e *Enforcer) RemoveRules(rules [][]string) error {
	if e.sc.AutosaveEnabled() {
		e.sc.DisableAutosave()
		defer func() {
			e.sc.EnableAutosave()
			if err := e.sc.Flush(); err != nil {
				panic(err)
			}
		}()
	}
	for _, rule := range rules {
		if _, err := e.model.RemoveRule(rule); err != nil {
			return err
		}
	}
	return nil
}

func (e *Enforcer) splitParams(params ...interface{}) (ctx *Context, request []interface{}, err error) {
	request = []interface{}{}
	options := []ContextOption{}

	for _, value := range params {
		switch v := value.(type) {
		case ContextOption:
			options = append(options, v)
		default:
			request = append(request, v)
		}
	}

	ctx, err = NewContext(e.model, options...)
	return ctx, request, err
}

// Enforce decides whether to allow or deny a request
// It is possible to pass ContextOptions, everything else will be treated as a request value
func (e *Enforcer) Enforce(params ...interface{}) (bool, error) {
	ctx, rvals, err := e.splitParams(params...)
	if err != nil {
		return false, err
	}
	return e.EnforceWithContext(ctx, rvals...)
}

func (e *Enforcer) EnforceWithContext(ctx *Context, rvals ...interface{}) (bool, error) {
	return e.enforce(ctx, rvals)
}

// Filter will fetch all rules which match the given request
// It is possible to pass ContextOptions, everything else will be treated as a request value
// The effect of rules is not considered.
//
// Get all permissons from alice:
//  e.Filter(SetMatcher([]string{"p.user == \"alice\""}))
// Get all grouping rules in domain1:
//  e.Filter(SetMatcher([]string{"g.domain == \"domain1\""}))
func (e *Enforcer) Filter(params ...interface{}) ([]types.Rule, error) {
	ctx, rvals, err := e.splitParams(params...)
	if err != nil {
		return nil, err
	}
	return e.FilterWithContext(ctx, rvals...)
}

func (e *Enforcer) FilterWithContext(ctx *Context, rvals ...interface{}) ([]types.Rule, error) {
	rules := []types.Rule{}
	err := e.RangeMatchesWithContext(ctx, rvals, func(rule types.Rule) bool {
		rules = append(rules, rule)
		return true
	})
	return rules, err
}

func (e *Enforcer) RangeMatches(params []interface{}, fn func(rule types.Rule) bool) error {
	ctx, rvals, err := e.splitParams(params...)
	if err != nil {
		return err
	}
	return e.RangeMatchesWithContext(ctx, rvals, fn)
}

func (e *Enforcer) RangeMatchesWithContext(ctx *Context, rvals []interface{}, fn func(rule types.Rule) bool) error {
	return e.model.RangeMatches(ctx.matcher, ctx.rDef, rvals, fn)
}

func (e *Enforcer) enforce(ctx *Context, rvals []interface{}) (bool, error) {
	def, _ := e.model.GetDef(model.P_SEC, ctx.matcher.GetPolicyKey())
	pDef := def.(*defs.PolicyDef)
	res := eft.Indeterminate
	effects := []types.Effect{}
	matches := []types.Rule{}

	var eftErr error = nil
	err := e.RangeMatchesWithContext(ctx, rvals, func(rule types.Rule) bool {
		effect := pDef.GetEft(rule)

		effects = append(effects, effect)
		matches = append(matches, rule)

		res, _, eftErr = ctx.effector.MergeEffects(effects, matches, false)

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
		res, _, _ = ctx.effector.MergeEffects(effects, matches, true)
	}

	return res == eft.Allow, nil
}

func (e *Enforcer) GetModel() model.IModel {
	return e.model
}
