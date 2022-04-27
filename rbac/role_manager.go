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

package rbac

import (
	"strings"
	"sync"

	"github.com/abichinger/fastac/util"
)

const REDUNDANT_ROLE = "redundant_role"

// RoleManager provides a default implementation for the RoleManager interface
type RoleManager struct {
	allRoles           *sync.Map
	maxHierarchyLevel  int
	matchingFunc       MatchingFunc
	domainMatchingFunc MatchingFunc
	matchingFuncCache  *util.SyncLRUCache
}

// NewRoleManager is the constructor for creating an instance of the
// default RoleManager implementation.
func NewRoleManager(maxHierarchyLevel int) *RoleManager {
	rm := RoleManager{}
	_ = rm.Clear() //init allRoles and matchingFuncCache
	rm.maxHierarchyLevel = maxHierarchyLevel
	return &rm
}

// use this constructor to avoid rebuild of SetMatcher
func newRoleManagerWithMatchingFunc(maxHierarchyLevel int, fn MatchingFunc) *RoleManager {
	rm := NewRoleManager(maxHierarchyLevel)
	rm.matchingFunc = fn
	return rm
}

// rebuilds role cache
func (rm *RoleManager) rebuild() {
	roles := rm.allRoles
	_ = rm.Clear()
	rangeLinks(roles, func(name1, name2 string, domain ...string) bool {
		_, _ = rm.AddLink(name1, name2, domain...)
		return true
	})
}

func (rm *RoleManager) match(str string, pattern string) bool {
	cacheKey := strings.Join([]string{str, pattern}, "$$")
	if v, has := rm.matchingFuncCache.Get(cacheKey); has {
		return v.(bool)
	} else {
		matched := rm.matchingFunc(str, pattern)
		rm.matchingFuncCache.Put(cacheKey, matched)
		return matched
	}
}

func (rm *RoleManager) rangeMatchingRoles(name string, isPattern bool, fn func(role *Role) bool) {
	rm.allRoles.Range(func(key, value interface{}) bool {
		name2 := key.(string)
		if isPattern && name != name2 && rm.match(name2, name) {
			fn(value.(*Role))
		} else if !isPattern && name != name2 && rm.match(name, name2) {
			fn(value.(*Role))
		}
		return true
	})
}

func (rm *RoleManager) load(name interface{}) (value *Role, ok bool) {
	if r, ok := rm.allRoles.Load(name); ok {
		return r.(*Role), true
	}
	return nil, false
}

// loads or creates a role
func (rm *RoleManager) getRole(name string) (r *Role, created bool) {
	var role *Role
	var ok bool

	if role, ok = rm.load(name); !ok {
		role = newRole(name)
		rm.allRoles.Store(name, role)

		if rm.matchingFunc != nil {
			rm.rangeMatchingRoles(name, false, func(r *Role) bool {
				r.addMatch(role)
				return true
			})

			rm.rangeMatchingRoles(name, true, func(r *Role) bool {
				role.addMatch(r)
				return true
			})
		}
	}

	return role, !ok
}

func loadAndDelete(m *sync.Map, name string) (value interface{}, loaded bool) {
	value, loaded = m.Load(name)
	if loaded {
		m.Delete(name)
	}
	return value, loaded
}

func (rm *RoleManager) removeRole(name string) {
	if role, ok := loadAndDelete(rm.allRoles, name); ok {
		role.(*Role).removeMatches()
	}
}

// SetMatcher support use pattern in g
func (rm *RoleManager) SetMatcher(fn MatchingFunc) {
	rm.matchingFunc = fn
	rm.rebuild()
}

// SetDomainMatcher support use domain pattern in g
func (rm *RoleManager) SetDomainMatcher(fn MatchingFunc) {
	rm.domainMatchingFunc = fn
}

// Clear clears all stored data and resets the role manager to the initial state.
func (rm *RoleManager) Clear() error {
	rm.matchingFuncCache = util.NewSyncLRUCache(100)
	rm.allRoles = &sync.Map{}
	return nil
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// aka role: name1 inherits role: name2.
func (rm *RoleManager) AddLink(name1 string, name2 string, domains ...string) (bool, error) {
	user, _ := rm.getRole(name1)
	role, _ := rm.getRole(name2)

	if len(domains) > 0 && domains[0] == REDUNDANT_ROLE {
		user.redundant.LoadOrStore(name2, nil)
	}

	return user.addRole(role), nil
}

// DeleteLink deletes the inheritance link between role: name1 and role: name2.
// aka role: name1 does not inherit role: name2 any more.
func (rm *RoleManager) DeleteLink(name1 string, name2 string, domains ...string) (bool, error) {
	user, _ := rm.getRole(name1)
	role, _ := rm.getRole(name2)

	if len(domains) > 0 && domains[0] == REDUNDANT_ROLE {
		user.redundant.Delete(name2)
	}

	return user.removeRole(role), nil
}

// HasLink determines whether role: name1 inherits role: name2.
func (rm *RoleManager) HasLink(name1 string, name2 string, domains ...string) (bool, error) {
	if name1 == name2 || (rm.matchingFunc != nil && rm.match(name1, name2)) {
		return true, nil
	}

	user, userCreated := rm.getRole(name1)
	role, roleCreated := rm.getRole(name2)

	if userCreated {
		defer rm.removeRole(user.name)
	}
	if roleCreated {
		defer rm.removeRole(role.name)
	}

	return rm.hasLinkHelper(role.name, map[string]*Role{user.name: user}, rm.maxHierarchyLevel), nil
}

func (rm *RoleManager) hasLinkHelper(targetName string, roles map[string]*Role, level int) bool {
	if level <= 0 || len(roles) == 0 {
		return false
	}

	nextRoles := map[string]*Role{}
	for _, role := range roles {
		if targetName == role.name || (rm.matchingFunc != nil && rm.match(role.name, targetName)) {
			return true
		}
		role.rangeRoles(func(key, value interface{}) bool {
			nextRoles[key.(string)] = value.(*Role)
			return true
		})
	}

	return rm.hasLinkHelper(targetName, nextRoles, level-1)
}

// GetRoles gets the roles that a user inherits.
func (rm *RoleManager) GetRoles(name string, domains ...string) ([]string, error) {
	user, created := rm.getRole(name)
	if created {
		defer rm.removeRole(user.name)
	}
	return user.getRoles(), nil
}

// GetUsers gets the users of a role.
// domain is an unreferenced parameter here, may be used in other implementations.
func (rm *RoleManager) GetUsers(name string, domain ...string) ([]string, error) {
	role, created := rm.getRole(name)
	if created {
		defer rm.removeRole(role.name)
	}
	return role.getUsers(), nil
}

// GetDomains gets domains that a user has
func (rm *RoleManager) GetDomains(name string) ([]string, error) {
	return []string{}, nil
}

// GetAllDomains gets all domains
func (rm *RoleManager) GetAllDomains() ([]string, error) {
	return []string{}, nil
}

func rangeLinks(users *sync.Map, fn func(name1, name2 string, domain ...string) bool) {
	users.Range(func(_, value interface{}) bool {
		user := value.(*Role)
		user.roles.Range(func(key, _ interface{}) bool {
			roleName := key.(string)
			if _, ok := user.redundant.Load(roleName); !ok {
				return fn(user.name, roleName)
			}
			return true
		})
		return true
	})
}

func (rm *RoleManager) Range(fn func(name1, name2 string, domain ...string) bool) {
	rangeLinks(rm.allRoles, fn)
}
