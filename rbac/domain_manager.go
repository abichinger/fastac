package rbac

import (
	"strings"
	"sync"

	"example.com/fastac/util"
)

const defaultDomain string = "RoleManager"

type DomainManager struct {
	rmMap              *sync.Map
	maxHierarchyLevel  int
	matchingFunc       MatchingFunc
	domainMatchingFunc MatchingFunc
	matchingFuncCache  *util.SyncLRUCache
}

// NewDomainManager is the constructor for creating an instance of the
// default DomainManager implementation.
func NewDomainManager(maxHierarchyLevel int) *DomainManager {
	dm := &DomainManager{}
	_ = dm.Clear() // init rmMap and rmCache
	dm.maxHierarchyLevel = maxHierarchyLevel
	return dm
}

func (dm *DomainManager) SetMatcher(fn MatchingFunc) {
	dm.matchingFunc = fn
	dm.rmMap.Range(func(key, value interface{}) bool {
		value.(IRoleManager).SetMatcher(fn)
		return true
	})
}

// SetDomainMatcher support use domain pattern in g
func (dm *DomainManager) SetDomainMatcher(fn MatchingFunc) {
	dm.domainMatchingFunc = fn
	dm.rmMap.Range(func(key, value interface{}) bool {
		value.(IRoleManager).SetDomainMatcher(fn)
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
	dm.matchingFuncCache = util.NewSyncLRUCache(100)
	return nil
}

func (dm *DomainManager) getDomain(domains ...string) (domain string, subdomains []string, err error) {
	if len(domains) == 0 {
		return defaultDomain, []string{}, nil
	}
	return domains[0], domains[1:], nil
}

func (dm *DomainManager) match(str string, pattern string) bool {
	cacheKey := strings.Join([]string{str, pattern}, "$$")
	if v, has := dm.matchingFuncCache.Get(cacheKey); has {
		return v.(bool)
	} else {
		matched := dm.domainMatchingFunc(str, pattern)
		dm.matchingFuncCache.Put(cacheKey, matched)
		return matched
	}
}

func (dm *DomainManager) rangeAffectedRoleManagers(domain string, fn func(rm IRoleManager)) {
	if dm.domainMatchingFunc != nil {
		dm.rmMap.Range(func(key, value interface{}) bool {
			domain2 := key.(string)
			if domain != domain2 && dm.match(domain2, domain) {
				fn(value.(IRoleManager))
			}
			return true
		})
	}
}

func (dm *DomainManager) load(name interface{}) (value IRoleManager, ok bool) {
	if r, ok := dm.rmMap.Load(name); ok {
		return r.(IRoleManager), true
	}
	return nil, false
}

// load or create a RoleManager instance of domain
func (dm *DomainManager) getRoleManager(domain string, store bool, subdomains ...string) IRoleManager {
	var rm IRoleManager
	var ok bool

	if rm, ok = dm.load(domain); !ok {
		if domain != defaultDomain {
			rm = NewDomainManager(dm.maxHierarchyLevel - 1)
			rm.SetMatcher(dm.matchingFunc)
			rm.SetDomainMatcher(dm.domainMatchingFunc)
		} else {
			rm = newRoleManagerWithMatchingFunc(dm.maxHierarchyLevel-1, dm.matchingFunc)
		}
		if store {
			dm.rmMap.Store(domain, rm)
		}
		if dm.domainMatchingFunc != nil {
			dm.rmMap.Range(func(key, value interface{}) bool {
				domain2 := key.(string)
				rm2 := value.(IRoleManager)
				if domain != domain2 && dm.match(domain, domain2) {
					rm.CopyFrom(rm2)
				}
				return true
			})
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

	dm.rangeAffectedRoleManagers(domain, func(rm IRoleManager) {
		_, _ = rm.AddLink(name1, name2, subdomains...)
	})
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

	dm.rangeAffectedRoleManagers(domain, func(rm IRoleManager) {
		_, _ = rm.DeleteLink(name1, name2, subdomains...)
	})
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

func (dm *DomainManager) CopyFrom(other IRoleManager) {
	other.Range(func(name1, name2 string, domain ...string) bool {
		_, _ = dm.AddLink(name1, name2, domain...)
		return true
	})
}
