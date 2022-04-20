package model

import (
	"example.com/fastac/api"
	"example.com/fastac/model/defs"
	e "example.com/fastac/model/effector"
	m "example.com/fastac/model/matcher"
	p "example.com/fastac/model/policy"
	"example.com/fastac/rbac"
)

type IString interface {
	String() string
}

type IClear interface {
	Clear() error
}

type IRuleManagement interface {
	IClear
	api.IAddRule
	api.IAddRules
	api.IRemoveRule
	api.IRemoveRules
}

type IAddDef interface {
	AddDef(sec byte, key string, value string) bool
}

type IRemoveDef interface {
	RemoveDef(sec byte, key string) bool
}

type IModel interface {
	GetRoleManager(key string) (rbac.IRoleManager, bool)
	SetRoleManager(key string, rm rbac.IRoleManager)

	GetPolicy(key string) (*p.Policy, bool)
	SetPolicy(key string, policy *p.Policy)

	GetEffector(key string) (e.Effector, bool)
	SetEffector(key string, eft e.Effector)

	GetMatcher(key string) (*m.Matcher, bool)
	SetMatcher(key string, matcher *m.Matcher)

	GetRequestDef(key string) (*defs.RequestDef, bool)
	SetRequestDef(key string, def *defs.RequestDef)

	ClearPolicy()
}
