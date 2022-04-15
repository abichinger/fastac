package model

import "example.com/fastac/rbac"

type IModel interface {
	AddDef(sec byte, key string, value string) bool
	RemoveDef(sec byte, key string, value string) bool

	GetRoleManager(key string) rbac.RoleManager
	SetRoleManager(key string, rm rbac.RoleManager)

	GetEffector(key string) Effector
	SetEffector(key string, eft Effector)

	AddRule(rule []string)
	RemoveRule(rule []string)
	ClearPolicy()
}
