package fastac

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/storage/adapter"
	"github.com/abichinger/fastac/util"
	"github.com/stretchr/testify/assert"
)

func TestAdapterInterface(t *testing.T) {
	a := adapter.NewFileAdapter("examples/rbac_policy.csv")
	e, err := NewEnforcer("examples/rbac_model.conf", nil)
	if err != nil {
		t.Error(err.Error())
	}
	e.SetAdapter(a)
	if err := e.LoadPolicy(); err != nil {
		t.Error(err.Error())
	}

	tmpPolicy := "tmp.csv"
	a = adapter.NewFileAdapter(tmpPolicy)
	defer os.Remove(tmpPolicy)

	e.SetAdapter(a)

	if err := e.SavePolicy(); err != nil {
		t.Error(err.Error())
	}

	result, err2 := ioutil.ReadFile(tmpPolicy)
	if err2 != nil {
		t.Error(err.Error())
	}

	expected, err3 := ioutil.ReadFile("examples/rbac_policy.csv")
	if err3 != nil {
		t.Error(err.Error())
	}

	filter := func(rules []string) []string {
		res := []string{}
		for _, rule := range rules {
			if rule == "" {
				continue
			}
			res = append(res, rule)
		}
		return res
	}

	assert.ElementsMatch(t, filter(strings.Split(string(result), "\n")), filter(strings.Split(string(expected), "\n")))
}

func TestOptions(t *testing.T) {

	tests := []struct {
		name     string
		model    interface{}
		adapter  interface{}
		apply    bool
		autosave bool
		storage  bool
		expected []bool //autosave, storage
	}{
		{
			"default",
			"examples/basic_model.conf",
			"examples/basic_policy.csv",
			false,
			false,
			false,
			[]bool{false, true},
		},
		{
			"default (no adapter)",
			"examples/basic_model.conf",
			nil,
			false,
			false,
			false,
			[]bool{false, false},
		},
		{
			"enable all",
			"examples/basic_model.conf",
			"examples/basic_policy.csv",
			true,
			true,
			true,
			[]bool{true, true},
		},
		{
			"disable all",
			"examples/basic_model.conf",
			"examples/basic_policy.csv",
			true,
			false,
			false,
			[]bool{false, false},
		},
		{
			"enable all (no adapter)",
			"examples/basic_model.conf",
			nil,
			true,
			true,
			true,
			[]bool{true, true},
		},
	}

	for _, test := range tests {
		t.Run("constructor", func(t *testing.T) {
			var e *Enforcer
			var err error

			if test.apply {
				e, err = NewEnforcer(test.model, test.adapter, OptionAutosave(test.autosave), OptionStorage(test.storage))
			} else {
				e, err = NewEnforcer(test.model, test.adapter)
			}

			if err != nil {
				t.Error(err.Error())
			}

			sc := e.GetStorageController()
			results := []bool{sc.AutosaveEnabled(), sc.Enabled()}
			assert.Equal(t, test.expected, results)
		})
		t.Run("SetOption", func(t *testing.T) {
			e, err := NewEnforcer(test.model, test.adapter)
			if err != nil {
				t.Error(err.Error())
			}

			if test.apply {
				_ = e.SetOption(OptionAutosave(test.autosave))
				_ = e.SetOption(OptionStorage(test.storage))
			}

			sc := e.GetStorageController()
			results := []bool{sc.AutosaveEnabled(), sc.Enabled()}
			assert.Equal(t, test.expected, results)
		})
	}

}

func TestEnforce(t *testing.T) {

	dom1Admin := defs.NewMatcherDef("m5", "g(r5.sub, \"admin\", \"domain1\")")

	tests := []struct {
		model    string
		policy   interface{}
		matchter interface{}
		effector interface{}
		rDef     interface{}
		requests [][]interface{}
		expected []bool
	}{
		{
			"examples/rbac_with_domains_model.conf",
			"examples/rbac_with_domains_policy.csv",
			nil,
			nil,
			nil,
			[][]interface{}{
				{"alice", "domain1", "data1", "read"},
				{"alice", "domain2", "data2", "read"},
			},
			[]bool{true, false},
		},
		{
			"examples/rbac_with_domains_model.conf",
			"examples/rbac_with_domains_policy.csv",
			dom1Admin,
			nil,
			defs.NewRequestDef("r5", "sub"),
			[][]interface{}{
				{"alice"},
				{"bob"},
				{"john"},
			},
			[]bool{true, false, false},
		},
		{
			"examples/rbac_with_deny_model.conf",
			"examples/rbac_with_deny_policy.csv",
			nil,
			"!some(where(p.eft==deny))",
			nil,
			[][]interface{}{
				{"alice", "data1", "write"},
				{"alice", "data2", "write"},
				{"alice", "data3", "write"},
			},
			[]bool{true, false, true},
		},
		{
			"examples/basic_model.conf",
			nil,
			"r.sub.Age > 50",
			nil,
			nil,
			[][]interface{}{
				{map[string]interface{}{"Age": 60}},
				{map[string]interface{}{"Age": 40}},
			},
			[]bool{true, false},
		},
		{
			"examples/basic_model.conf",
			nil,
			"123.456",
			nil,
			nil,
			[][]interface{}{
				{},
			},
			[]bool{false},
		},
	}

	for _, test := range tests {
		e, err := NewEnforcer(test.model, test.policy)
		if err != nil {
			t.Error(err.Error())
		}

		options := []interface{}{SetMatcher(test.matchter), SetRequestDef(test.rDef), SetEffector(test.effector)}
		results := []bool{}
		for _, request := range test.requests {
			res, err := e.Enforce(append(options, request...)...)
			if err != nil {
				t.Error(err.Error())
			}
			results = append(results, res)
		}
		assert.Equal(t, test.expected, results)
	}
}

func TestFilter(t *testing.T) {

	mDef := defs.NewMatcherDef("m5", "p.act == r5.action")

	tests := []struct {
		model    string
		policy   string
		matchter interface{}
		rDef     interface{}
		request  []interface{}
		expected []string
	}{
		{
			"examples/rbac_with_domains_model.conf",
			"examples/rbac_with_domains_policy.csv",
			"p.sub == \"admin\" && p.dom == \"domain1\"",
			"r",
			[]interface{}{},
			[]string{
				"p,admin,domain1,data1,read",
				"p,admin,domain1,data1,write",
			},
		},
		{
			"examples/rbac_with_domains_model.conf",
			"examples/rbac_with_domains_policy.csv",
			"g.domain == \"domain1\"",
			nil,
			[]interface{}{},
			[]string{
				"g,alice,admin,domain1",
			},
		},
		{
			"examples/rbac_with_domains_model.conf",
			"examples/rbac_with_domains_policy.csv",
			nil,
			nil,
			[]interface{}{"admin", "domain1", "data1", "read"},
			[]string{
				"p,admin,domain1,data1,read",
			},
		},
		{
			"examples/rbac_with_domains_model.conf",
			"examples/rbac_with_domains_policy.csv",
			mDef,
			defs.NewRequestDef("r5", "action"),
			[]interface{}{"read"},
			[]string{
				"p,admin,domain1,data1,read",
				"p,admin,domain2,data2,read",
			},
		},
		{
			"examples/pathmatch_model.conf",
			"examples/pathmatch_policy.csv",
			"pathMatch(\"/alice_data/resource2\", p.obj)",
			nil,
			[]interface{}{},
			[]string{
				"p,alice,/alice_data/*,GET",
				"p,bob,/alice_data/resource2,GET",
			},
		},
		{
			"examples/multiple_policy_definitions_model.conf",
			"examples/multiple_policy_definitions_policy.csv",
			"p2.eft == \"deny\"",
			nil,
			[]interface{}{},
			[]string{
				"p2,r2.sub.Age > 60 && r2.sub.Age < 100,/data1,read,deny",
			},
		},
		{
			"examples/basic_model.conf",
			"examples/basic_policy.csv",
			"true",
			nil,
			[]interface{}{},
			[]string{
				"p,alice,data1,read",
				"p,bob,data2,write",
			},
		},
		{
			"examples/basic_model.conf",
			"examples/basic_policy.csv",
			"false",
			nil,
			[]interface{}{},
			[]string{},
		},
	}

	for _, test := range tests {
		e, err := NewEnforcer(test.model, test.policy)
		if err != nil {
			t.Error(err.Error())
		}

		options := []interface{}{SetMatcher(test.matchter), SetRequestDef(test.rDef)}
		rules, err := e.Filter(append(options, test.request...)...)
		if err != nil {
			t.Error(err.Error())
		}

		assert.ElementsMatch(t, util.Join2D(rules, ","), test.expected)
	}

}
