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

func (e *Enforcer) AddPolicy(params ...interface{}) (bool, error) {
	return e.AddNamedPolicy("p", params...)
}

func (e *Enforcer) AddNamedPolicy(pKey string, params ...interface{}) (bool, error) {
	rule := model.Rule{}
	for _, param := range params {
		rule = append(rule, param.(string))
	}
	return true, e.m.AddPolicyRule(pKey, rule)
}

func (e *Enforcer) AddGroupingPolicy(params ...interface{}) (bool, error) {
	return e.AddNamedGroupingPolicy("g", params...)
}

func (e *Enforcer) AddNamedGroupingPolicy(gKey string, params ...interface{}) (bool, error) {
	rule := model.Rule{}
	for _, param := range params {
		rule = append(rule, param.(string))
	}
	return true, e.m.AddRoleRule(gKey, rule)
}

func (e *Enforcer) Enforce(rvals ...interface{}) (bool, error) {
	return e.m.Enforce("m", "r", "e", rvals)
}
