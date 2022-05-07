package fastac_test

import (
	"github.com/abichinger/fastac"
	"github.com/abichinger/fastac/model"
	"github.com/abichinger/fastac/model/fm"
)

//the model uses a custom MatchingFunc named customPathMatch
var example_functions_model = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && customPathMatch(r.obj, p.obj) && r.act == p.act`

var example_functions_policy = [][]string{
	{"p", "alice", "*", "GET"},
	{"p", "alice", "/user/alice", "PATCH"},
}

// ExampleFunctions shows how to use a custom util.MatchingFunc
func Example_functions() {

	//customPathMatch needs to be registered before loading the model
	fm.SetFunction("customPathMatch", func(arguments ...interface{}) (interface{}, error) {
		rObj := arguments[0].(string)
		rSub := arguments[1].(string)

		if rSub == "*" {
			return true, nil
		}
		return rObj == rSub, nil
	})

	//create enforcer and add rules
	m := model.NewModel()
	_ = m.LoadModelFromText(example_functions_model)
	e, _ := fastac.NewEnforcer(m, nil)
	_ = e.AddRules(example_functions_policy)

	//perform some requests
	printReq(e, "alice", "/user/alice/entry/1", "GET")
	printReq(e, "bob", "/user/alice/entry/1", "GET")
	printReq(e, "alice", "/user/alice", "PATCH")
	printReq(e, "bob", "/user/alice", "PATCH")

	// Output: alice, /user/alice/entry/1, GET => allow
	// bob, /user/alice/entry/1, GET => deny
	// alice, /user/alice, PATCH => allow
	// bob, /user/alice, PATCH => deny
}
