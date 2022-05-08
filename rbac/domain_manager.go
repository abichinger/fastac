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

const defaultDomain string = "RoleManager"

type DomainManager struct {
	rmMap             *sync.Map
	patternMap        *sync.Map
	maxHierarchyLevel int
	matcher           util.IMatcher
	domainMatcher     util.IMatcher
	matchingFuncCache *util.SyncLRUCache
}

// NewDomainManager is the constructor for creating an instance of the
// default DomainManager implementation.
func NewDomainManager(maxHierarchyLevel int) *DomainManager {
	dm := &DomainManager{}
	_ = dm.Clear() // init rmMap and rmCache
	dm.maxHierarchyLevel = maxHierarchyLevel
	return dm
}

func (dm *DomainManager) SetMatcher(matcher util.IMatcher) {
	dm.matcher = matcher
	dm.rmMap.Range(func(key, value interface{}) bool {
		value.(IDefaultRoleManager).SetMatcher(matcher)
		return true
	})
}

// SetDomainMatcher support use domain pattern in g
func (dm *DomainManager) SetDomainMatcher(matcher util.IMatcher) {
	dm.domainMatcher = matcher
	dm.rmMap.Range(func(key, value interface{}) bool {
		value.(IDefaultRoleManager).SetDomainMatcher(matcher)
		return true
	})
	dm.rebuild()
}

// clears the map of RoleManagers
func (dm *DomainManager) rebuild() {
	rmMap := dm.rmMap
	_ = dm.Clear()
	dm.rangeLinks(rmMap, func(name1, name2 string, domain ...string) bool {
		_, _ = dm.AddLink(name1, name2, domain...)
		return true
	})
}

//Clear clears all stored data and resets the role manager to the initial state.
func (dm *DomainManager) Clear() error {
	dm.rmMap = &sync.Map{}
	dm.patternMap = &sync.Map{}
	dm.matchingFuncCache = util.NewSyncLRUCache(100)
	return nil
}

func (dm *DomainManager) getDomain(domains ...string) (domain string, subdomains []string, err error) {
	if len(domains) == 0 {
		return defaultDomain, []string{}, nil
	} else if domains[0] == REDUNDANT_ROLE {
		return defaultDomain, []string{REDUNDANT_ROLE}, nil
	}
	return domains[0], domains[1:], nil
}

func (dm *DomainManager) match(str string, pattern string) bool {
	cacheKey := strings.Join([]string{str, pattern}, "$$")
	if v, has := dm.matchingFuncCache.Get(cacheKey); has {
		return v.(bool)
	} else {
		matched := dm.domainMatcher.Match(str, pattern)
		dm.matchingFuncCache.Put(cacheKey, matched)
		return matched
	}
}

func (dm *DomainManager) load(name interface{}) (value IDefaultRoleManager, ok bool) {
	if r, ok := dm.rmMap.Load(name); ok {
		return r.(IDefaultRoleManager), true
	}
	return nil, false
}

func (dm *DomainManager) rangeMatchingRMs(pattern string, fn func(rm IRoleManager)) {
	dm.rmMap.Range(func(key, value interface{}) bool {
		domain := key.(string)
		if pattern != domain && dm.match(domain, pattern) {
			fn(value.(IRoleManager))
		}
		return true
	})
}

func (dm *DomainManager) rangeMatchingPatterns(domain string, fn func(rm IRoleManager)) {
	dm.patternMap.Range(func(key, _ interface{}) bool {
		pattern := key.(string)
		if pattern != domain && dm.match(domain, pattern) {
			value, _ := dm.load(pattern)
			fn(value)
		}
		return true
	})
}

// load or create a RoleManager instance of domain
func (dm *DomainManager) getRoleManager(domain string, store bool, subdomains ...string) IRoleManager {
	var rm IDefaultRoleManager
	var ok bool

	if rm, ok = dm.load(domain); !ok {
		if domain != defaultDomain {
			rm = NewDomainManager(dm.maxHierarchyLevel - 1)
			rm.SetMatcher(dm.matcher)
			rm.SetDomainMatcher(dm.domainMatcher)
		} else {
			rm = newRoleManagerWithMatchingFunc(dm.maxHierarchyLevel-1, dm.matcher)
		}
		if store {
			dm.rmMap.Store(domain, rm)
		}
		if dm.domainMatcher != nil {
			if dm.domainMatcher.IsPattern(domain) {
				dm.patternMap.Store(domain, nil)
			} else {
				dm.rangeMatchingPatterns(domain, func(rm2 IRoleManager) {
					rm2.Range(func(name1, name2 string, domain ...string) bool {
						_, _ = rm.AddLink(name1, name2, append(domain, REDUNDANT_ROLE)...)
						return true
					})
				})
			}
		}
	}
	return rm
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// aka role: name1 inherits role: name2.
func (dm *DomainManager) AddLink(name1 string, name2 string, domains ...string) (bool, error) {
	domain, subdomains, err := dm.getDomain(domains...)
	if err != nil {
		return false, err
	}
	roleManager := dm.getRoleManager(domain, true, subdomains...) //create role manager if it does not exist
	added, _ := roleManager.AddLink(name1, name2, subdomains...)

	if dm.domainMatcher != nil && dm.domainMatcher.IsPattern(domain) {
		dm.rangeMatchingRMs(domain, func(rm IRoleManager) {
			_, _ = rm.AddLink(name1, name2, append(subdomains, REDUNDANT_ROLE)...)
		})
	}
	return added, nil
}

// DeleteLink deletes the inheritance link between role: name1 and role: name2.
// aka role: name1 does not inherit role: name2 any more.
func (dm *DomainManager) DeleteLink(name1 string, name2 string, domains ...string) (bool, error) {
	domain, subdomains, err := dm.getDomain(domains...)
	if err != nil {
		return false, err
	}
	roleManager := dm.getRoleManager(domain, true, subdomains...) //create role manager if it does not exist
	removed, _ := roleManager.DeleteLink(name1, name2, subdomains...)

	if dm.domainMatcher != nil && dm.domainMatcher.IsPattern(domain) {
		dm.rangeMatchingRMs(domain, func(rm IRoleManager) {
			_, _ = rm.DeleteLink(name1, name2, append(subdomains, REDUNDANT_ROLE)...)
		})
	}
	return removed, nil
}

// HasLink determines whether role: name1 inherits role: name2.
func (dm *DomainManager) HasLink(name1 string, name2 string, domains ...string) (bool, error) {
	domain, subdomains, err := dm.getDomain(domains...)
	if err != nil {
		return false, err
	}
	rm := dm.getRoleManager(domain, false, subdomains...)
	return rm.HasLink(name1, name2, subdomains...)
}

// GetRoles gets the roles that a subject inherits.
func (dm *DomainManager) GetRoles(name string, domains ...string) ([]string, error) {
	domain, subdomains, err := dm.getDomain(domains...)
	if err != nil {
		return nil, err
	}
	rm := dm.getRoleManager(domain, false, subdomains...)
	return rm.GetRoles(name, subdomains...)
}

// GetUsers gets the users of a role.
func (dm *DomainManager) GetUsers(name string, domains ...string) ([]string, error) {
	domain, subdomains, err := dm.getDomain(domains...)
	if err != nil {
		return nil, err
	}
	rm := dm.getRoleManager(domain, false, subdomains...)
	return rm.GetUsers(name, subdomains...)
}

func (dm *DomainManager) resolveRoleManager(domains ...string) *RoleManager {
	var domain string
	domainManager := dm
	domain, subdomains, _ := dm.getDomain(domains...)

	for domain != defaultDomain {
		domainManager = domainManager.getRoleManager(domain, false, subdomains...).(*DomainManager)
		domain, subdomains, _ = dm.getDomain(subdomains...)
	}

	return domainManager.getRoleManager(domain, false, subdomains...).(*RoleManager)
}

// GetDomains gets domains that a user has
func (dm *DomainManager) GetDomains(name string) ([]string, error) {
	domainArr, err := dm.getAllDomainsHelper()
	if err != nil {
		return nil, err
	}

	res := []string{}
	for _, domains := range domainArr {
		rm := dm.resolveRoleManager(domains...)
		role, created := rm.getRole(name)
		if created {
			defer rm.removeRole(role.name)
		}
		if len(role.getUsers()) > 0 || len(role.getRoles()) > 0 {
			res = append(res, strings.Join(domains, "/"))
		}
	}
	return res, nil
}

func (dm *DomainManager) getAllDomainsHelper() ([][]string, error) {
	domainMap := make(map[string][]string)
	dm.Range(func(name1, name2 string, domains ...string) bool {
		domain := strings.Join(domains, "/")
		domainMap[domain] = domains
		return true
	})
	domains := [][]string{}
	for _, domain := range domainMap {
		domains = append(domains, domain)
	}
	return domains, nil
}

// GetAllDomains gets all domains
func (dm *DomainManager) GetAllDomains() ([]string, error) {
	domains, err := dm.getAllDomainsHelper()
	if err != nil {
		return nil, err
	}

	res := []string{}
	for _, domain := range domains {
		res = append(res, strings.Join(domain, "/"))
	}
	return res, nil
}

func (dm *DomainManager) rangeLinks(rmMap *sync.Map, fn func(name1, name2 string, domain ...string) bool) {
	rmMap.Range(func(key, value interface{}) bool {
		roleManager := value.(IRoleManager)
		domains := []string{}
		if d := key.(string); d != defaultDomain {
			domains = append(domains, d)
		}

		roleManager.Range(func(name1, name2 string, domain ...string) bool {
			fn(name1, name2, append(domains, domain...)...)
			return true
		})

		return true
	})
}

func (dm *DomainManager) Range(fn func(name1, name2 string, domain ...string) bool) {
	dm.rangeLinks(dm.rmMap, fn)
}
