package model

import (
	"github.com/abichinger/fastac/api"
	"github.com/abichinger/fastac/model/defs"
	e "github.com/abichinger/fastac/model/effector"
	m "github.com/abichinger/fastac/model/matcher"
	p "github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/rbac"
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
