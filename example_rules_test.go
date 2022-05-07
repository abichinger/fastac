package fastac_test

import (
	"fmt"
	"sort"

	"github.com/abichinger/fastac"
	"github.com/abichinger/fastac/util"
)

var example_rules_policy = [][]string{
	{"p", "alice", "data1", "read"},
	{"p", "alice", "data1", "write"},
	{"p", "bob", "data2", "read"},
	{"p", "bob", "data2", "write"},
	{"p", "alice", "data3", "read"},
	{"p", "bob", "data3", "read"},
	{"p", "manager", "data3", "write"},
	{"g", "bob", "manager"},
}

// ExampleManagePolicy demonstrates the usage of functions to modify the policy
func Example_managePolicy() {

	//create enforcer with rbac model and empty policy
	e, _ := fastac.NewEnforcer("examples/rbac_model.conf", nil)

	//add multiple rules at once
	_ = e.AddRules(example_rules_policy)

	//remove all rules of user bob
	bobRules, _ := e.Filter(fastac.SetMatcher(`p.sub == "bob"`))
	bobGroupingRules, _ := e.Filter(fastac.SetMatcher(`g.user == "bob"`))
	_ = e.RemoveRules(append(bobRules, bobGroupingRules...))

	//make alice a manager
	alice_manager := []string{"g", "alice", "manager"}
	added, _ := e.AddRule(alice_manager)
	if added {
		fmt.Println("rule added successfully")
	}

	//get a list of all rules
	var allRules [][]string
	e.GetModel().RangeRules(func(rule []string) bool {
		allRules = append(allRules, rule)
		return true
	})

	//sort and print rules
	allRulesStr := util.Join2D(allRules, ", ")
	sort.Strings(allRulesStr)
	for _, rule := range allRulesStr {
		fmt.Println(rule)
	}

	// Output: rule added successfully
	// g, alice, manager
	// p, alice, data1, read
	// p, alice, data1, write
	// p, alice, data3, read
	// p, manager, data3, write
}
