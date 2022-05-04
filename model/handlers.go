package model

import (
	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/effector"
	"github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/rbac"
)

func addPolicyDef(m *Model, key string, arguments string) error {
	def := defs.NewPolicyDef(key, arguments)
	m.defs[P_SEC][key] = def
	m.pMap[key] = policy.NewPolicy(def)
	return nil
}

func removePolicyDef(m *Model, key string) error {
	delete(m.defs[P_SEC], key)
	delete(m.pMap, key)
	return nil
}

func addMatcherDef(m *Model, key string, matcher string) error {
	mDef := defs.NewMatcherDef(key, matcher)
	m.defs[M_SEC][key] = mDef
	return nil
}

func removeMatcherDef(m *Model, key string) error {
	delete(m.defs[M_SEC], key)
	delete(m.mMap, key)
	return nil
}

func addRoleDef(m *Model, key, arguments string) error {
	def := defs.NewRoleDef(key, arguments)
	m.defs[G_SEC][key] = def
	var rm rbac.IRoleManager
	if def.NArgs() == 2 {
		rm = rbac.NewRoleManager(10)
	} else {
		rm = rbac.NewDomainManager(10)
	}
	m.rpMap[key] = rbac.NewRolePolicy(rm)
	m.fm.SetFunction(key, rbac.GenerateGFunction(rm))
	return nil
}

func removeRoleDef(m *Model, key string) error {
	delete(m.defs[G_SEC], key)
	delete(m.rpMap, key)
	m.fm.RemoveFunction(key)
	return nil
}

func addRequestDef(m *Model, key, arguments string) error {
	m.defs[R_SEC][key] = defs.NewRequestDef(key, arguments)
	return nil
}

func removeRequestDef(m *Model, key string) error {
	delete(m.defs[R_SEC], key)
	return nil
}

func addEffectDef(m *Model, key, expr string) error {
	def := defs.NewEffectDef(key, expr)
	m.defs[E_SEC][key] = def
	m.eMap[key] = effector.NewEffector(def)
	return nil
}

func removeEffectDef(m *Model, key string) error {
	delete(m.defs[E_SEC], key)
	delete(m.eMap, key)
	return nil
}
