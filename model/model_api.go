package model

import "example.com/fastac/rbac"

type IModel interface {
	AddDef(sec byte, key string, value string) bool
	RemoveDef(sec byte, key string) bool

	GetRoleManager(key string) (rbac.IRoleManager, bool)
	SetRoleManager(key string, rm rbac.IRoleManager)

	GetPolicy(key string) (*Policy, bool)
	SetPolicy(key string, policy *Policy)

	GetEffector(key string) (Effector, bool)
	SetEffector(key string, eft Effector)

	AddRule(rule []string) (bool, error)
	RemoveRule(rule []string) (bool, error)
	ClearPolicy()
}
