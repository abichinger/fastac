package fastac_test

import (
	"fmt"
	"strings"

	"github.com/abichinger/fastac"
	"github.com/abichinger/fastac/model"
	"github.com/abichinger/fastac/rbac"
	"github.com/abichinger/fastac/util"
)

//the model uses the built-in MatchingFunc pathMatch
var example_matcher_model = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && pathMatch(r.obj, p.obj) && r.act == p.act`

var example_matcher_policy = [][]string{
	{"p", "role:user", "/user/:uid/entry/:eid", "GET"},
	{"p", "user:alice", "/user/alice/*", "POST"},
	{"p", "role:admin", "/user/:uid/entry/:eid", "DELETE"},
	{"g", "reg:user:.*", "role:user"},
	{"g", "user:alice", "role:admin"},
}

func printReq(e *fastac.Enforcer, params ...interface{}) {
	b, _ := e.Enforce(params...)
	var rule []string
	for _, param := range params {
		rule = append(rule, param.(string))
	}
	if b {
		fmt.Printf("%s => allow\n", strings.Join(rule, ", "))
	} else {
		fmt.Printf("%s => deny\n", strings.Join(rule, ", "))
	}
}

// ExampleMatchers shows the usage of util.MatchingFunc and util.IMatcher
func Example_matchers() {

	//create enforcer and add rules
	m := model.NewModel()
	_ = m.LoadModelFromText(example_matcher_model)
	e, _ := fastac.NewEnforcer(m, nil)
	_ = e.AddRules(example_matcher_policy)

	//get the default rolemanager
	rm, _ := e.GetModel().GetRoleManager("g")

	// set a role matcher.
	// create a PrefixMatcher. PrefixMatcher implements the interface util.IMatcher
	// each regex pattern needs to be marked with the prefix "reg:"
	roleMatcher := util.NewPrefixMatcher("reg:", util.RegexMatch)
	rm.(rbac.IDefaultRoleManager).SetMatcher(roleMatcher)

	printReq(e, "user:alice", "/user/joe/entry/1", "GET") //allow, because user:alice has role:user
	printReq(e, "user:alice", "/user/alice/entry/2", "POST")
	printReq(e, "user:alice", "/user/bob/entry/3", "POST")
	printReq(e, "user:alice", "/user/bob/entry/3", "DELETE")
	printReq(e, "user:bob", "/user/alice/entry/2", "DELETE")

	// Output: user:alice, /user/joe/entry/1, GET => allow
	// user:alice, /user/alice/entry/2, POST => allow
	// user:alice, /user/bob/entry/3, POST => deny
	// user:alice, /user/bob/entry/3, DELETE => allow
	// user:bob, /user/alice/entry/2, DELETE => deny
}
