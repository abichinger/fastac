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
)

// Role represents the data structure for a role in RBAC.
type Role struct {
	name      string
	roles     *sync.Map
	users     *sync.Map
	matched   *sync.Map
	matchedBy *sync.Map
	redundant *sync.Map //string set of redundant roles
}

func newRole(name string) *Role {
	r := Role{}
	r.name = name
	r.roles = &sync.Map{}
	r.users = &sync.Map{}
	r.matched = &sync.Map{}
	r.matchedBy = &sync.Map{}
	r.redundant = &sync.Map{}
	return &r
}

func (r *Role) hasRole(role *Role) (ok bool) {
	_, ok = r.roles.Load(role.name)
	return
}

func (r *Role) addRole(role *Role) bool {
	if r.hasRole(role) {
		return false
	}
	r.roles.Store(role.name, role)
	role.addUser(r)
	return true
}

func (r *Role) removeRole(role *Role) bool {
	if !r.hasRole(role) {
		return false
	}
	r.roles.Delete(role.name)
	role.removeUser(r)
	return true
}

//should only be called inside addRole
func (r *Role) addUser(user *Role) {
	r.users.Store(user.name, user)
}

//should only be called inside removeRole
func (r *Role) removeUser(user *Role) {
	r.users.Delete(user.name)
}

func (r *Role) addMatch(role *Role) {
	r.matched.Store(role.name, role)
	role.matchedBy.Store(r.name, r)
}

func (r *Role) removeMatch(role *Role) {
	r.matched.Delete(role.name)
	role.matchedBy.Delete(r.name)
}

func (r *Role) removeMatches() {
	r.matched.Range(func(key, value interface{}) bool {
		r.removeMatch(value.(*Role))
		return true
	})
	r.matchedBy.Range(func(key, value interface{}) bool {
		value.(*Role).removeMatch(r)
		return true
	})
}

func (r *Role) rangeRoles(fn func(key, value interface{}) bool) {
	r.roles.Range(fn)
	r.roles.Range(func(key, value interface{}) bool {
		role := value.(*Role)
		role.matched.Range(fn)
		return true
	})
	r.matchedBy.Range(func(key, value interface{}) bool {
		role := value.(*Role)
		role.roles.Range(fn)
		return true
	})
}

func (r *Role) rangeUsers(fn func(key, value interface{}) bool) {
	r.users.Range(fn)
	r.users.Range(func(key, value interface{}) bool {
		role := value.(*Role)
		role.matched.Range(fn)
		return true
	})
	r.matchedBy.Range(func(key, value interface{}) bool {
		role := value.(*Role)
		role.users.Range(fn)
		return true
	})
}

func (r *Role) toString() string {
	roles := r.getRoles()

	if len(roles) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(r.name)
	sb.WriteString(" < ")
	if len(roles) != 1 {
		sb.WriteString("(")
	}

	for i, role := range roles {
		if i == 0 {
			sb.WriteString(role)
		} else {
			sb.WriteString(", ")
			sb.WriteString(role)
		}
	}

	if len(roles) != 1 {
		sb.WriteString(")")
	}

	return sb.String()
}

func (r *Role) getRoles() []string {
	names := []string{}
	r.rangeRoles(func(key, value interface{}) bool {
		names = append(names, key.(string))
		return true
	})
	return names
}

func (r *Role) getUsers() []string {
	names := []string{}
	r.rangeUsers(func(key, value interface{}) bool {
		names = append(names, key.(string))
		return true
	})
	return names
}
