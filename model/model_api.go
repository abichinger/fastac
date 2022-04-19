package model

import (
	e "example.com/fastac/model/effector"
	p "example.com/fastac/model/policy"
	"example.com/fastac/rbac"
)

type IModel interface {
	AddDef(sec byte, key string, value string) bool
	RemoveDef(sec byte, key string) bool

	GetRoleManager(key string) (rbac.IRoleManager, bool)
	SetRoleManager(key string, rm rbac.IRoleManager)

	GetPolicy(key string) (*p.Policy, bool)
	SetPolicy(key string, policy *p.Policy)

	GetEffector(key string) (e.Effector, bool)
	SetEffector(key string, eft e.Effector)

	AddRule(rule []string) (bool, error)
	RemoveRule(rule []string) (bool, error)
	ClearPolicy()
}
