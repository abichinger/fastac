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
	"fmt"
	"testing"

	"github.com/abichinger/fastac/util"
	"github.com/stretchr/testify/assert"
)

func testRole(t *testing.T, rm IRoleManager, name1 string, name2 string, res bool) {
	t.Helper()
	myRes, _ := rm.HasLink(name1, name2)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", name1, name2, !res, res)
	}
}

func testDomainRole(t *testing.T, rm IRoleManager, res bool, name1 string, name2 string, domains ...string) {
	t.Helper()
	myRes, _ := rm.HasLink(name1, name2, domains...)

	if myRes != res {
		t.Errorf("%v :: %s < %s: %t, supposed to be %t", domains, name1, name2, !res, res)
	}
}

func testPrintRoles(t *testing.T, rm IRoleManager, name string, res []string) {
	t.Helper()
	myRes, _ := rm.GetRoles(name)
	t.Logf("%s: %s", name, myRes)

	assert.ElementsMatch(t, myRes, res)
}

func testPrintUsers(t *testing.T, rm IRoleManager, name string, res []string) {
	t.Helper()
	myRes, _ := rm.GetUsers(name)
	t.Logf("%s: %s", name, myRes)

	assert.ElementsMatch(t, myRes, res)
}

func testPrintRolesWithDomain(t *testing.T, rm IRoleManager, name string, domain string, res []string) {
	t.Helper()
	myRes, _ := rm.GetRoles(name, domain)

	assert.ElementsMatch(t, myRes, res)
}

func testAddLink(t *testing.T, rm IRoleManager, expected bool, name1 string, name2 string, domains ...string) {
	t.Helper()
	b, err := rm.AddLink(name1, name2, domains...)
	if err != nil {
		t.Error(err.Error())
	}
	assert.Equal(t, expected, b)
}

func testDeleteLink(t *testing.T, rm IRoleManager, expected bool, name1 string, name2 string, domains ...string) {
	t.Helper()
	b, err := rm.DeleteLink(name1, name2, domains...)
	if err != nil {
		t.Error(err.Error())
	}
	assert.Equal(t, expected, b)
}

func TestRole(t *testing.T) {
	rm := NewRoleManager(3)
	testAddLink(t, rm, true, "u1", "g1")
	testAddLink(t, rm, true, "u2", "g1")
	testAddLink(t, rm, true, "u3", "g2")
	testAddLink(t, rm, true, "u4", "g2")
	testAddLink(t, rm, true, "u4", "g3")
	testAddLink(t, rm, true, "g1", "g3")

	// Current role inheritance tree:
	//             g3    g2
	//            /  \  /  \
	//          g1    u4    u3
	//         /  \
	//       u1    u2

	testRole(t, rm, "u1", "g1", true)
	testRole(t, rm, "u1", "g2", false)
	testRole(t, rm, "u1", "g3", true)
	testRole(t, rm, "u2", "g1", true)
	testRole(t, rm, "u2", "g2", false)
	testRole(t, rm, "u2", "g3", true)
	testRole(t, rm, "u3", "g1", false)
	testRole(t, rm, "u3", "g2", true)
	testRole(t, rm, "u3", "g3", false)
	testRole(t, rm, "u4", "g1", false)
	testRole(t, rm, "u4", "g2", true)
	testRole(t, rm, "u4", "g3", true)

	testPrintRoles(t, rm, "u1", []string{"g1"})
	testPrintRoles(t, rm, "u2", []string{"g1"})
	testPrintRoles(t, rm, "u3", []string{"g2"})
	testPrintRoles(t, rm, "u4", []string{"g2", "g3"})
	testPrintRoles(t, rm, "g1", []string{"g3"})
	testPrintRoles(t, rm, "g2", []string{})
	testPrintRoles(t, rm, "g3", []string{})

	testDeleteLink(t, rm, true, "g1", "g3")
	testDeleteLink(t, rm, true, "u4", "g2")

	// Current role inheritance tree after deleting the links:
	//             g3    g2
	//               \     \
	//          g1    u4    u3
	//         /  \
	//       u1    u2

	testRole(t, rm, "u1", "g1", true)
	testRole(t, rm, "u1", "g2", false)
	testRole(t, rm, "u1", "g3", false)
	testRole(t, rm, "u2", "g1", true)
	testRole(t, rm, "u2", "g2", false)
	testRole(t, rm, "u2", "g3", false)
	testRole(t, rm, "u3", "g1", false)
	testRole(t, rm, "u3", "g2", true)
	testRole(t, rm, "u3", "g3", false)
	testRole(t, rm, "u4", "g1", false)
	testRole(t, rm, "u4", "g2", false)
	testRole(t, rm, "u4", "g3", true)

	testPrintRoles(t, rm, "u1", []string{"g1"})
	testPrintRoles(t, rm, "u2", []string{"g1"})
	testPrintRoles(t, rm, "u3", []string{"g2"})
	testPrintRoles(t, rm, "u4", []string{"g3"})
	testPrintRoles(t, rm, "g1", []string{})
	testPrintRoles(t, rm, "g2", []string{})
	testPrintRoles(t, rm, "g3", []string{})
}

func TestDomainRole(t *testing.T) {
	rm := NewDomainManager(10)
	testAddLink(t, rm, true, "u1", "g1", "domain1")
	testAddLink(t, rm, true, "u2", "g1", "domain1")
	testAddLink(t, rm, true, "u3", "admin", "domain2")
	testAddLink(t, rm, true, "u4", "admin", "domain2")
	testAddLink(t, rm, true, "u4", "admin", "domain1")
	testAddLink(t, rm, true, "g1", "admin", "domain1")

	// Current role inheritance tree:
	//       domain1:admin    domain2:admin
	//            /       \  /       \
	//      domain1:g1     u4         u3
	//         /  \
	//       u1    u2

	testDomainRole(t, rm, true, "u1", "g1", "domain1")
	testDomainRole(t, rm, false, "u1", "g1", "domain2")
	testDomainRole(t, rm, true, "u1", "admin", "domain1")
	testDomainRole(t, rm, false, "u1", "admin", "domain2")

	testDomainRole(t, rm, true, "u2", "g1", "domain1")
	testDomainRole(t, rm, false, "u2", "g1", "domain2")
	testDomainRole(t, rm, true, "u2", "admin", "domain1")
	testDomainRole(t, rm, false, "u2", "admin", "domain2")

	testDomainRole(t, rm, false, "u3", "g1", "domain1")
	testDomainRole(t, rm, false, "u3", "g1", "domain2")
	testDomainRole(t, rm, false, "u3", "admin", "domain1")
	testDomainRole(t, rm, true, "u3", "admin", "domain2")

	testDomainRole(t, rm, false, "u4", "g1", "domain1")
	testDomainRole(t, rm, false, "u4", "g1", "domain2")
	testDomainRole(t, rm, true, "u4", "admin", "domain1")
	testDomainRole(t, rm, true, "u4", "admin", "domain2")

	testDeleteLink(t, rm, true, "g1", "admin", "domain1")
	testDeleteLink(t, rm, true, "u4", "admin", "domain2")

	// Current role inheritance tree after deleting the links:
	//       domain1:admin    domain2:admin
	//                    \          \
	//      domain1:g1     u4         u3
	//         /  \
	//       u1    u2

	testDomainRole(t, rm, true, "u1", "g1", "domain1")
	testDomainRole(t, rm, false, "u1", "g1", "domain2")
	testDomainRole(t, rm, false, "u1", "admin", "domain1")
	testDomainRole(t, rm, false, "u1", "admin", "domain2")

	testDomainRole(t, rm, true, "u2", "g1", "domain1")
	testDomainRole(t, rm, false, "u2", "g1", "domain2")
	testDomainRole(t, rm, false, "u2", "admin", "domain1")
	testDomainRole(t, rm, false, "u2", "admin", "domain2")

	testDomainRole(t, rm, false, "u3", "g1", "domain1")
	testDomainRole(t, rm, false, "u3", "g1", "domain2")
	testDomainRole(t, rm, false, "u3", "admin", "domain1")
	testDomainRole(t, rm, true, "u3", "admin", "domain2")

	testDomainRole(t, rm, false, "u4", "g1", "domain1")
	testDomainRole(t, rm, false, "u4", "g1", "domain2")
	testDomainRole(t, rm, true, "u4", "admin", "domain1")
	testDomainRole(t, rm, false, "u4", "admin", "domain2")
}

func TestClear(t *testing.T) {
	rm := NewRoleManager(3)
	testAddLink(t, rm, true, "u1", "g1")
	testAddLink(t, rm, true, "u2", "g1")
	testAddLink(t, rm, true, "u3", "g2")
	testAddLink(t, rm, true, "u4", "g2")
	testAddLink(t, rm, true, "u4", "g3")
	testAddLink(t, rm, true, "g1", "g3")

	// Current role inheritance tree:
	//             g3    g2
	//            /  \  /  \
	//          g1    u4    u3
	//         /  \
	//       u1    u2

	_ = rm.Clear()

	// All data is cleared.
	// No role inheritance now.

	testRole(t, rm, "u1", "g1", false)
	testRole(t, rm, "u1", "g2", false)
	testRole(t, rm, "u1", "g3", false)
	testRole(t, rm, "u2", "g1", false)
	testRole(t, rm, "u2", "g2", false)
	testRole(t, rm, "u2", "g3", false)
	testRole(t, rm, "u3", "g1", false)
	testRole(t, rm, "u3", "g2", false)
	testRole(t, rm, "u3", "g3", false)
	testRole(t, rm, "u4", "g1", false)
	testRole(t, rm, "u4", "g2", false)
	testRole(t, rm, "u4", "g3", false)
}

func TestPatternRole(t *testing.T) {
	rm := NewRoleManager(10)
	rm.SetMatcher(util.RegexMatch)

	links := [][]string{
		{"u1", "g1"},
		{"u2", "g\\d+"},
		{"u\\d+", "users"},
		{"g\\d+", "root"},
	}

	for _, link := range links {
		testAddLink(t, rm, true, link[0], link[1])
	}

	testRole(t, rm, "u1", "g1", true)
	testRole(t, rm, "u1", "g2", false)
	testRole(t, rm, "u1", "g3", false)
	testRole(t, rm, "u1", "users", true)
	testRole(t, rm, "u1", "root", true)

	testRole(t, rm, "u2", "g1", true)
	testRole(t, rm, "u2", "g2", true)
	testRole(t, rm, "u2", "g3", true)
	testRole(t, rm, "u2", "users", true)
	testRole(t, rm, "u2", "root", true)

	testRole(t, rm, "u3", "g1", false)
	testRole(t, rm, "u3", "g2", false)
	testRole(t, rm, "u3", "g3", false)
	testRole(t, rm, "u3", "users", true)
	testRole(t, rm, "u3", "root", false)

	rules := [][]string{}
	rm.Range(func(name1, name2 string, domain ...string) bool {
		rules = append(rules, []string{name1, name2})
		return true
	})

	assert.ElementsMatch(t, util.Join2D(links, ","), util.Join2D(rules, ","))
}

func TestDomainPatternRole(t *testing.T) {
	rm := NewDomainManager(10)
	rm.SetDomainMatcher(util.KeyMatch2)

	links := [][]string{
		{"u1", "g1", "domain1"},
		{"u2", "g1", "domain2"},
		{"u3", "g1", "*"},
		{"u4", "g2", "domain3"},
	}

	for _, link := range links {
		testAddLink(t, rm, true, link[0], link[1], link[2])
	}
	// Current role inheritance tree after deleting the links:
	//       domain1:g1    domain2:g1			domain3:g2
	//		   /      \    /      \					|
	//	 domain1:u1    *:g1     domain2:u2		domain3:u4
	// 					|
	// 				   *:u3
	testDomainRole(t, rm, true, "u1", "g1", "domain1")
	testDomainRole(t, rm, false, "u2", "g1", "domain1")
	testDomainRole(t, rm, true, "u2", "g1", "domain2")
	testDomainRole(t, rm, true, "u3", "g1", "domain1")
	testDomainRole(t, rm, true, "u3", "g1", "domain2")
	testDomainRole(t, rm, false, "u1", "g2", "domain1")
	testDomainRole(t, rm, true, "u4", "g2", "domain3")
	testDomainRole(t, rm, false, "u3", "g2", "domain3")

	testPrintRolesWithDomain(t, rm, "u3", "domain1", []string{"g1"})
	testPrintRolesWithDomain(t, rm, "u1", "domain1", []string{"g1"})
	testPrintRolesWithDomain(t, rm, "u3", "domain2", []string{"g1"})
	testPrintRolesWithDomain(t, rm, "u1", "domain2", []string{})
	testPrintRolesWithDomain(t, rm, "u4", "domain3", []string{"g2"})

	rules := [][]string{}
	rm.Range(func(name1, name2 string, domain ...string) bool {
		rules = append(rules, []string{name1, name2, domain[0]})
		return true
	})

	assert.ElementsMatch(t, util.Join2D(links, ","), util.Join2D(rules, ","))

	testDeleteLink(t, rm, true, "u3", "g1", "*")
	testAddLink(t, rm, true, "u3", "g1", "domain1")
	links[2] = []string{"u3", "g1", "domain1"}

	testDomainRole(t, rm, true, "u3", "g1", "domain1")
	testDomainRole(t, rm, false, "u3", "g1", "domain2")
	testDomainRole(t, rm, false, "u3", "g2", "domain3")

	rules = [][]string{}
	rm.Range(func(name1, name2 string, domain ...string) bool {
		rules = append(rules, []string{name1, name2, domain[0]})
		return true
	})

	assert.ElementsMatch(t, util.Join2D(links, ","), util.Join2D(rules, ","))
}

func TestAllMatchingFunc(t *testing.T) {
	rm := NewDomainManager(10)
	rm.SetMatcher(util.KeyMatch2)
	rm.SetDomainMatcher(util.KeyMatch2)

	testAddLink(t, rm, true, "/book/:id", "book_group", "*")
	// Current role inheritance tree after deleting the links:
	//  		*:book_group
	//				|
	// 			*:/book/:id
	testDomainRole(t, rm, true, "/book/1", "book_group", "domain1")
	testDomainRole(t, rm, true, "/book/2", "book_group", "domain1")
}

func TestMatchingFuncOrder(t *testing.T) {
	rm := NewRoleManager(10)
	rm.SetMatcher(util.RegexMatch)

	testAddLink(t, rm, true, "g\\d+", "root")
	testAddLink(t, rm, true, "u1", "g1")
	testRole(t, rm, "u1", "root", true)

	_ = rm.Clear()

	testAddLink(t, rm, true, "u1", "g1")
	testAddLink(t, rm, true, "g\\d+", "root")
	testRole(t, rm, "u1", "root", true)

	_ = rm.Clear()

	testAddLink(t, rm, true, "u1", "g\\d+")
	testRole(t, rm, "u1", "g1", true)
	testRole(t, rm, "u1", "g2", true)
}

func TestDomainMatchingFuncWithDifferentDomain(t *testing.T) {
	rm := NewDomainManager(10)
	rm.SetDomainMatcher(util.KeyMatch)

	testAddLink(t, rm, true, "alice", "editor", "*")
	testAddLink(t, rm, true, "editor", "admin", "domain1")

	testDomainRole(t, rm, true, "alice", "admin", "domain1")
	testDomainRole(t, rm, false, "alice", "admin", "domain2")
}

func TestTemporaryRoles(t *testing.T) {
	rm := NewRoleManager(10)
	rm.SetMatcher(util.RegexMatch)

	testAddLink(t, rm, true, "u\\d+", "user")

	for i := 0; i < 10; i++ {
		testRole(t, rm, fmt.Sprintf("u%d", i), "user", true)
	}

	testPrintUsers(t, rm, "user", []string{"u\\d+"})
	testPrintRoles(t, rm, "u1", []string{"user"})

	testAddLink(t, rm, true, "u1", "manager")

	for i := 10; i < 20; i++ {
		testRole(t, rm, fmt.Sprintf("u%d", i), "user", true)
	}

	testPrintUsers(t, rm, "user", []string{"u\\d+", "u1"})
	testPrintRoles(t, rm, "u1", []string{"user", "manager"})
}

func TestSubdomain(t *testing.T) {
	rm := NewDomainManager(10)
	rm.SetDomainMatcher(util.RegexMatch)

	testAddLink(t, rm, true, "alice", "admin", "domain1", "sub1")
	testAddLink(t, rm, false, "alice", "admin", "domain1", "sub1")
	testAddLink(t, rm, true, "alice", "user", "domain2", "sub2")
	testAddLink(t, rm, true, "alice", "user", ".*", "sub1")
	testAddLink(t, rm, true, "bob", "user", "domain1")
	testAddLink(t, rm, true, "bob", "user", "domain2", "sub1")
	testAddLink(t, rm, true, "bob", "user", "domain2", "sub2")

	allDomains := []string{"domain1/sub1", "domain2/sub1", "domain2/sub2", "domain1", ".*/sub1"}
	allDomainsRes, _ := rm.GetAllDomains()
	assert.ElementsMatch(t, allDomains, allDomainsRes)

	bobDomains := []string{"domain2/sub1", "domain2/sub2", "domain1"}
	bobDomainsRes, _ := rm.GetDomains("bob")
	assert.ElementsMatch(t, bobDomains, bobDomainsRes)

	testDomainRole(t, rm, false, "alice", "admin", "domain1")
	testDomainRole(t, rm, true, "alice", "admin", "domain1", "sub1")
	testDomainRole(t, rm, false, "alice", "admin", "domain1", "sub2")
	testDomainRole(t, rm, false, "alice", "admin", "domain2", "sub1")
	testDomainRole(t, rm, false, "alice", "admin", "domain2", "sub2")

	testDomainRole(t, rm, false, "alice", "user", "domain1")
	testDomainRole(t, rm, true, "alice", "user", "domain1", "sub1")
	testDomainRole(t, rm, false, "alice", "user", "domain1", "sub2")
	testDomainRole(t, rm, true, "alice", "user", "domain2", "sub1")
	testDomainRole(t, rm, true, "alice", "user", "domain2", "sub2")
	testDomainRole(t, rm, true, "alice", "user", "domain3", "sub1")
	testDomainRole(t, rm, false, "alice", "user", "domain3", "sub2")

	testDomainRole(t, rm, true, "bob", "user", "domain1")
	testDomainRole(t, rm, false, "bob", "user", "domain1", "sub1")
	testDomainRole(t, rm, false, "bob", "user", "domain1", "sub2")
	testDomainRole(t, rm, true, "bob", "user", "domain2", "sub1")
	testDomainRole(t, rm, true, "bob", "user", "domain2", "sub2")
	testDomainRole(t, rm, false, "bob", "user", "domain3", "sub1")
	testDomainRole(t, rm, false, "bob", "user", "domain3", "sub2")

	testDeleteLink(t, rm, true, "alice", "user", ".*", "sub1")
	testDeleteLink(t, rm, false, "alice", "user", ".*", "sub1")
	testDeleteLink(t, rm, true, "bob", "user", "domain2", "sub2")

	testDomainRole(t, rm, false, "alice", "admin", "domain1")
	testDomainRole(t, rm, true, "alice", "admin", "domain1", "sub1")
	testDomainRole(t, rm, false, "alice", "admin", "domain1", "sub2")
	testDomainRole(t, rm, false, "alice", "admin", "domain2", "sub1")
	testDomainRole(t, rm, false, "alice", "admin", "domain2", "sub2")

	testDomainRole(t, rm, false, "alice", "user", "domain1")
	testDomainRole(t, rm, false, "alice", "user", "domain1", "sub1")
	testDomainRole(t, rm, false, "alice", "user", "domain1", "sub2")
	testDomainRole(t, rm, false, "alice", "user", "domain2", "sub1")
	testDomainRole(t, rm, true, "alice", "user", "domain2", "sub2")
	testDomainRole(t, rm, false, "alice", "user", "domain3", "sub1")
	testDomainRole(t, rm, false, "alice", "user", "domain3", "sub2")

	testDomainRole(t, rm, true, "bob", "user", "domain1")
	testDomainRole(t, rm, false, "bob", "user", "domain1", "sub1")
	testDomainRole(t, rm, false, "bob", "user", "domain1", "sub2")
	testDomainRole(t, rm, true, "bob", "user", "domain2", "sub1")
	testDomainRole(t, rm, false, "bob", "user", "domain2", "sub2")
	testDomainRole(t, rm, false, "bob", "user", "domain3", "sub1")
	testDomainRole(t, rm, false, "bob", "user", "domain3", "sub2")
}
