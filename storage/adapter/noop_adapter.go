package adapter

import "github.com/abichinger/fastac/api"

type NoopAdapter struct{}

func (a *NoopAdapter) LoadPolicy(model api.IAddRuleBool) error { return nil }
func (a *NoopAdapter) SavePolicy(model api.IRangeRules) error  { return nil }
func (a *NoopAdapter) AddRule(rule []string) error             { return nil }
func (a *NoopAdapter) RemoveRule(rule []string) error          { return nil }
