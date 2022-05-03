// Copyright 2017 The casbin Authors. All Rights Reserved.
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

package fastac

import (
	"testing"

	"github.com/abichinger/fastac/model/fm"
	"github.com/abichinger/fastac/rbac"
	"github.com/abichinger/fastac/util"
)

func testEnforce(t *testing.T, e *Enforcer, sub interface{}, obj interface{}, act string, res bool) {
	t.Helper()
	if myRes, _ := e.Enforce(sub, obj, act); myRes != res {
		t.Errorf("%s, %v, %s: %t, supposed to be %t", sub, obj, act, myRes, res)
	}
}

func testEnforceWithoutUsers(t *testing.T, e *Enforcer, obj string, act string, res bool) {
	t.Helper()
	if myRes, _ := e.Enforce(obj, act); myRes != res {
		t.Errorf("%s, %s: %t, supposed to be %t", obj, act, myRes, res)
	}
}

func testDomainEnforce(t *testing.T, e *Enforcer, sub string, dom string, obj string, act string, res bool) {
	t.Helper()
	if myRes, _ := e.Enforce(sub, dom, obj, act); myRes != res {
		t.Errorf("%s, %s, %s, %s: %t, supposed to be %t", sub, dom, obj, act, myRes, res)
	}
}

func TestBasicModel(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestBasicModelWithoutSpaces(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model_without_spaces.conf", "examples/basic_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestBasicModelNoPolicy(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", nil)

	testEnforce(t, e, "alice", "data1", "read", false)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", false)
}

func TestBasicModelWithRoot(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
	testEnforce(t, e, "root", "data1", "read", true)
	testEnforce(t, e, "root", "data1", "write", true)
	testEnforce(t, e, "root", "data2", "read", true)
	testEnforce(t, e, "root", "data2", "write", true)
}

func TestBasicModelWithRootNoPolicy(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_with_root_model.conf", nil)

	testEnforce(t, e, "alice", "data1", "read", false)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", false)
	testEnforce(t, e, "root", "data1", "read", true)
	testEnforce(t, e, "root", "data1", "write", true)
	testEnforce(t, e, "root", "data2", "read", true)
	testEnforce(t, e, "root", "data2", "write", true)
}

func TestBasicModelWithoutUsers(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_without_users_model.conf", "examples/basic_without_users_policy.csv")

	testEnforceWithoutUsers(t, e, "data1", "read", true)
	testEnforceWithoutUsers(t, e, "data1", "write", false)
	testEnforceWithoutUsers(t, e, "data2", "read", false)
	testEnforceWithoutUsers(t, e, "data2", "write", true)
}

func TestBasicModelWithoutResources(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_without_resources_model.conf", "examples/basic_without_resources_policy.csv")

	testEnforceWithoutUsers(t, e, "alice", "read", true)
	testEnforceWithoutUsers(t, e, "alice", "write", false)
	testEnforceWithoutUsers(t, e, "bob", "read", false)
	testEnforceWithoutUsers(t, e, "bob", "write", true)
}

func TestRBACModel(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestRBACModelWithResourceRoles(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", true)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestRBACModelWithDomains(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")

	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", true)
	testDomainEnforce(t, e, "alice", "domain1", "data1", "write", true)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "read", false)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "read", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", true)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "write", true)
}

func TestRBACModelWithDomainsAtRuntime(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_domains_model.conf", nil)

	_, _ = e.AddRule([]string{"p", "admin", "domain1", "data1", "read"})
	_, _ = e.AddRule([]string{"p", "admin", "domain1", "data1", "write"})
	_, _ = e.AddRule([]string{"p", "admin", "domain2", "data2", "read"})
	_, _ = e.AddRule([]string{"p", "admin", "domain2", "data2", "write"})

	_, _ = e.AddRule([]string{"g", "alice", "admin", "domain1"})
	_, _ = e.AddRule([]string{"g", "bob", "admin", "domain2"})

	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", true)
	testDomainEnforce(t, e, "alice", "domain1", "data1", "write", true)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "read", false)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "read", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", true)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "write", true)

	//Remove all policy rules related to domain1 and data1.
	rules, err := e.Filter(SetMatcher("p.dom == \"domain1\" && p.obj == \"data1\""))
	if err != nil {
		t.Error(err.Error())
	}
	_ = e.RemoveRules(rules)

	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", false)
	testDomainEnforce(t, e, "alice", "domain1", "data1", "write", false)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "read", false)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "read", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", true)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "write", true)

	// Remove the specified policy rule.
	_, _ = e.RemoveRule([]string{"p", "admin", "domain2", "data2", "read"})

	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", false)
	testDomainEnforce(t, e, "alice", "domain1", "data1", "write", false)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "read", false)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "read", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", false)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "write", true)
}

func TestRBACModelWithDomainsExtendAtRuntime(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")

	_, _ = e.AddRule([]string{"p", "admin", "domain3", "data1", "read"})
	_, _ = e.AddRule([]string{"g", "alice", "admin", "domain3"})

	testDomainEnforce(t, e, "alice", "domain3", "data1", "read", true)
	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", true)

	// Remove all policy rules related to domain1 and data1.
	rules, _ := e.Filter(SetMatcher("p.dom == \"domain1\" && p.obj == \"data1\""))
	if err := e.RemoveRules(rules); err != nil {
		t.Error(err.Error())
	}

	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", false)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", true)

	_, _ = e.RemoveRule([]string{"p", "admin", "domain2", "data2", "read"})
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", false)
}

func TestRBACModelWithDeny(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestRBACModelWithOnlyDeny(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_not_deny_model.conf", "examples/rbac_with_deny_policy.csv")

	testEnforce(t, e, "alice", "data2", "write", false)
}

func TestRBACModelExtendAtRuntime(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	//equivalent to: e.AddRule("g", "bob", "data2_admin")
	ok, err := e.AddRule([]string{"g", "bob", "data2_admin", "gets_ignored"})
	if !ok {
		t.Error("g, bob, data2_admin: should have been added")
	}
	if err != nil {
		t.Error(err.Error())
	}

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", true)
	testEnforce(t, e, "bob", "data2", "write", true)

	//equivalent to: e.RemoveRule("g", "bob", "data2_admin")
	ok, err = e.RemoveRule([]string{"g", "bob", "data2_admin", "gets_also_ignored"})
	if !ok {
		t.Error("g, bob, data2_admin: should have been removed")
	}
	if err != nil {
		t.Error(err.Error())
	}

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestRBACModelWithPattern(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv")

	// Here's a little confusing: the matching function here is not the custom function used in matcher.
	// It is the matching function used by "g" (and "g2", "g3" if any..)
	g2, _ := e.GetModel().GetRoleManager("g2")
	g2.SetMatcher(util.PathMatch)
	g1, _ := e.GetModel().GetRoleManager("g")
	g1.SetMatcher(util.PathMatch)

	b, _ := g1.HasLink("any_user", "*")
	t.Log(b)

	testEnforce(t, e, "any_user", "/pen3/1", "GET", true)
	testEnforce(t, e, "/book/user/1", "/pen4/1", "GET", true)

	testEnforce(t, e, "/book/user/1", "/pen4/1", "POST", true)
	testEnforce(t, e, "alice", "/book/1", "GET", true)
	testEnforce(t, e, "alice", "/book/2", "GET", true)
	testEnforce(t, e, "alice", "/pen/1", "GET", true)
	testEnforce(t, e, "alice", "/pen/2", "GET", false)
	testEnforce(t, e, "bob", "/book/1", "GET", false)
	testEnforce(t, e, "bob", "/book/2", "GET", false)
	testEnforce(t, e, "bob", "/pen/1", "GET", true)
	testEnforce(t, e, "bob", "/pen/2", "GET", true)

	g2.SetMatcher(util.PathMatch2)
	testEnforce(t, e, "alice", "/book2/1", "GET", true)
	testEnforce(t, e, "alice", "/book2/2", "GET", true)
	testEnforce(t, e, "alice", "/pen2/1", "GET", true)
	testEnforce(t, e, "alice", "/pen2/2", "GET", false)
	testEnforce(t, e, "bob", "/book2/1", "GET", false)
	testEnforce(t, e, "bob", "/book2/2", "GET", false)
	testEnforce(t, e, "bob", "/pen2/1", "GET", true)
	testEnforce(t, e, "bob", "/pen2/2", "GET", true)
}

type testCustomRoleManager struct{}

func NewCustomRoleManager() rbac.IRoleManager {
	return &testCustomRoleManager{}
}
func (rm *testCustomRoleManager) Clear() error { return nil }
func (rm *testCustomRoleManager) AddLink(name1 string, name2 string, domain ...string) (bool, error) {
	return false, nil
}
func (rm *testCustomRoleManager) DeleteLink(name1 string, name2 string, domain ...string) (bool, error) {
	return false, nil
}
func (rm *testCustomRoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
	if name1 == "alice" && name2 == "alice" {
		return true, nil
	} else if name1 == "alice" && name2 == "data2_admin" {
		return true, nil
	} else if name1 == "bob" && name2 == "bob" {
		return true, nil
	}
	return false, nil
}
func (rm *testCustomRoleManager) GetRoles(name string, domain ...string) ([]string, error) {
	return []string{}, nil
}
func (rm *testCustomRoleManager) GetUsers(name string, domain ...string) ([]string, error) {
	return []string{}, nil
}
func (rm *testCustomRoleManager) GetDomains(name string) ([]string, error)                  { return []string{}, nil }
func (rm *testCustomRoleManager) GetAllDomains() ([]string, error)                          { return []string{}, nil }
func (rm *testCustomRoleManager) PrintRoles() error                                         { return nil }
func (rm *testCustomRoleManager) SetMatcher(fn rbac.MatchingFunc)                           {}
func (rm *testCustomRoleManager) SetDomainMatcher(fn rbac.MatchingFunc)                     {}
func (rm *testCustomRoleManager) CopyFrom(other rbac.IRoleManager)                          {}
func (rm *testCustomRoleManager) Range(fn func(name1, name2 string, domain ...string) bool) {}
func (rm *testCustomRoleManager) String() string                                            { return "" }

func TestRBACModelWithCustomRoleManager(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	e.GetModel().SetRoleManager("g", NewCustomRoleManager())

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

type testResource struct {
	Name  string
	Owner string
}

func newTestResource(name string, owner string) testResource {
	r := testResource{}
	r.Name = name
	r.Owner = owner
	return r
}

func TestABACModel(t *testing.T) {
	e, _ := NewEnforcer("examples/abac_model.conf", nil)

	data1 := newTestResource("data1", "alice")
	data2 := map[string]interface{}{
		"Name":  "data2",
		"Owner": "bob",
	}

	testEnforce(t, e, "alice", data1, "read", true)
	testEnforce(t, e, "alice", data1, "write", true)
	testEnforce(t, e, "alice", data2, "read", false)
	testEnforce(t, e, "alice", data2, "write", false)
	testEnforce(t, e, "bob", data1, "read", false)
	testEnforce(t, e, "bob", data1, "write", false)
	testEnforce(t, e, "bob", data2, "read", true)
	testEnforce(t, e, "bob", data2, "write", true)
}

func TestPathMatchModel(t *testing.T) {
	e, _ := NewEnforcer("examples/pathmatch_model.conf", "examples/pathmatch_policy.csv")

	testEnforce(t, e, "alice", "/alice_data/resource1", "GET", true)
	testEnforce(t, e, "alice", "/alice_data/resource1", "POST", true)
	testEnforce(t, e, "alice", "/alice_data/resource2", "GET", true)
	testEnforce(t, e, "alice", "/alice_data/resource2", "POST", false)
	testEnforce(t, e, "alice", "/bob_data/resource1", "GET", false)
	testEnforce(t, e, "alice", "/bob_data/resource1", "POST", false)
	testEnforce(t, e, "alice", "/bob_data/resource2", "GET", false)
	testEnforce(t, e, "alice", "/bob_data/resource2", "POST", false)

	testEnforce(t, e, "bob", "/alice_data/resource1", "GET", false)
	testEnforce(t, e, "bob", "/alice_data/resource1", "POST", false)
	testEnforce(t, e, "bob", "/alice_data/resource2", "GET", true)
	testEnforce(t, e, "bob", "/alice_data/resource2", "POST", false)
	testEnforce(t, e, "bob", "/bob_data/resource1", "GET", false)
	testEnforce(t, e, "bob", "/bob_data/resource1", "POST", true)
	testEnforce(t, e, "bob", "/bob_data/resource2", "GET", false)
	testEnforce(t, e, "bob", "/bob_data/resource2", "POST", true)

	testEnforce(t, e, "cathy", "/cathy_data", "GET", true)
	testEnforce(t, e, "cathy", "/cathy_data", "POST", true)
	testEnforce(t, e, "cathy", "/cathy_data", "DELETE", false)

	testEnforce(t, e, "alice", "/alice_data2", "GET", false)
	testEnforce(t, e, "alice", "/alice_data2/resource1", "GET", true)
	testEnforce(t, e, "alice", "/alice_data2/resource1/info", "GET", false)
	testEnforce(t, e, "alice", "/alice_data2/myid/using/res_id", "GET", true)
}

func CustomFunction(key1 string, key2 string) bool {
	if key1 == "/alice_data2/myid/using/res_id" && key2 == "/alice_data/:resource" {
		return true
	} else if key1 == "/alice_data2/myid/using/res_id" && key2 == "/alice_data2/:id/using/:resId" {
		return true
	} else {
		return false
	}
}

func CustomFunctionWrapper(args ...interface{}) (interface{}, error) {
	key1 := args[0].(string)
	key2 := args[1].(string)

	return bool(CustomFunction(key1, key2)), nil
}

func TestKeyMatchCustomModel(t *testing.T) {
	fm.SetFunction("keyMatchCustom", CustomFunctionWrapper)

	e, err := NewEnforcer("examples/keymatch_custom_model.conf", "examples/pathmatch_policy.csv")
	if err != nil {
		t.Error(err.Error())
	}

	testEnforce(t, e, "alice", "/alice_data2/myid", "GET", false)
	testEnforce(t, e, "alice", "/alice_data2/myid/using/res_id", "GET", true)
}

func TestIPMatchModel(t *testing.T) {
	e, _ := NewEnforcer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv")

	testEnforce(t, e, "192.168.2.123", "data1", "read", true)
	testEnforce(t, e, "192.168.2.123", "data1", "write", false)
	testEnforce(t, e, "192.168.2.123", "data2", "read", false)
	testEnforce(t, e, "192.168.2.123", "data2", "write", false)

	testEnforce(t, e, "192.168.0.123", "data1", "read", false)
	testEnforce(t, e, "192.168.0.123", "data1", "write", false)
	testEnforce(t, e, "192.168.0.123", "data2", "read", false)
	testEnforce(t, e, "192.168.0.123", "data2", "write", false)

	testEnforce(t, e, "10.0.0.5", "data1", "read", false)
	testEnforce(t, e, "10.0.0.5", "data1", "write", false)
	testEnforce(t, e, "10.0.0.5", "data2", "read", false)
	testEnforce(t, e, "10.0.0.5", "data2", "write", true)

	testEnforce(t, e, "192.168.0.1", "data1", "read", false)
	testEnforce(t, e, "192.168.0.1", "data1", "write", false)
	testEnforce(t, e, "192.168.0.1", "data2", "read", false)
	testEnforce(t, e, "192.168.0.1", "data2", "write", false)
}

func TestGlobMatchModel(t *testing.T) {
	e, _ := NewEnforcer("examples/glob_model.conf", "examples/glob_policy.csv")
	testEnforce(t, e, "u1", "/foo/", "read", true)
	testEnforce(t, e, "u1", "/foo", "read", false)
	testEnforce(t, e, "u1", "/foo/subprefix", "read", true)
	testEnforce(t, e, "u1", "foo", "read", false)

	testEnforce(t, e, "u2", "/foosubprefix", "read", true)
	testEnforce(t, e, "u2", "/foo/subprefix", "read", false)
	testEnforce(t, e, "u2", "foo", "read", false)

	testEnforce(t, e, "u3", "/prefix/foo/subprefix", "read", true)
	testEnforce(t, e, "u3", "/prefix/foo/", "read", true)
	testEnforce(t, e, "u3", "/prefix/foo", "read", false)

	testEnforce(t, e, "u4", "/foo", "read", false)
	testEnforce(t, e, "u4", "foo", "read", true)
}

// func TestPriorityModel(t *testing.T) {
// 	e, _ := NewEnforcer("examples/priority_model.conf", "examples/priority_policy.csv")

// 	testEnforce(t, e, "alice", "data1", "read", true)
// 	testEnforce(t, e, "alice", "data1", "write", false)
// 	testEnforce(t, e, "alice", "data2", "read", false)
// 	testEnforce(t, e, "alice", "data2", "write", false)
// 	testEnforce(t, e, "bob", "data1", "read", false)
// 	testEnforce(t, e, "bob", "data1", "write", false)
// 	testEnforce(t, e, "bob", "data2", "read", true)
// 	testEnforce(t, e, "bob", "data2", "write", false)
// }

func TestPriorityModelIndeterminate(t *testing.T) {
	e, _ := NewEnforcer("examples/priority_model.conf", "examples/priority_indeterminate_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", false)
}

func TestRBACModelInMultiLines(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model_in_multi_line.conf", "examples/rbac_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

type testSub struct {
	Name string
	Age  int
}

func newTestSubject(name string, age int) testSub {
	s := testSub{}
	s.Name = name
	s.Age = age
	return s
}

func TestABACNotUsingPolicy(t *testing.T) {
	e, _ := NewEnforcer("examples/abac_not_using_policy_model.conf", "examples/abac_rule_effect_policy.csv")
	data1 := newTestResource("data1", "alice")
	data2 := newTestResource("data2", "bob")

	testEnforce(t, e, "alice", data1, "read", true)
	testEnforce(t, e, "alice", data1, "write", true)
	testEnforce(t, e, "alice", data2, "read", false)
	testEnforce(t, e, "alice", data2, "write", false)
}

func TestABACPolicy(t *testing.T) {
	e, _ := NewEnforcer("examples/abac_rule_model.conf", "examples/abac_rule_policy.csv")

	sub1 := newTestSubject("alice", 16)
	sub2 := newTestSubject("alice", 20)
	sub3 := newTestSubject("alice", 65)

	testEnforce(t, e, sub1, "/data1", "read", false)
	testEnforce(t, e, sub1, "/data2", "read", false)
	testEnforce(t, e, sub1, "/data1", "write", false)
	testEnforce(t, e, sub1, "/data2", "write", true)
	testEnforce(t, e, sub2, "/data1", "read", true)
	testEnforce(t, e, sub2, "/data2", "read", false)
	testEnforce(t, e, sub2, "/data1", "write", false)
	testEnforce(t, e, sub2, "/data2", "write", true)
	testEnforce(t, e, sub3, "/data1", "read", true)
	testEnforce(t, e, sub3, "/data2", "read", false)
	testEnforce(t, e, sub3, "/data1", "write", false)
	testEnforce(t, e, sub3, "/data2", "write", false)
}

func TestCommentModel(t *testing.T) {
	e, _ := NewEnforcer("examples/comment_model.conf", "examples/basic_policy.csv")
	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestDomainMatchModel(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_domain_pattern_model.conf", "examples/rbac_with_domain_pattern_policy.csv")
	rm, _ := e.GetModel().GetRoleManager("g")
	rm.SetDomainMatcher(util.PathMatch)

	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", true)
	testDomainEnforce(t, e, "alice", "domain1", "data1", "write", true)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "read", false)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "write", false)
	testDomainEnforce(t, e, "alice", "domain2", "data2", "read", true)
	testDomainEnforce(t, e, "alice", "domain2", "data2", "write", true)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "read", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", true)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "write", true)
}

func TestAllMatchModel(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_all_pattern_model.conf", "examples/rbac_with_all_pattern_policy.csv")
	rm, _ := e.GetModel().GetRoleManager("g")
	rm.SetMatcher(util.PathMatch)
	rm.SetDomainMatcher(util.PathMatch)

	testDomainEnforce(t, e, "alice", "domain1", "/book/1", "read", true)
	testDomainEnforce(t, e, "alice", "domain1", "/book/1", "write", false)
	testDomainEnforce(t, e, "alice", "domain2", "/book/1", "read", false)
	testDomainEnforce(t, e, "alice", "domain2", "/book/1", "write", true)
}
