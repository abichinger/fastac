package defs

import (
	"fmt"
	"testing"

	"github.com/abichinger/fastac/model/eft"
	"github.com/abichinger/fastac/model/types"
	"github.com/abichinger/govaluate"
	"github.com/stretchr/testify/assert"
)

func TestBuild(t *testing.T) {

	tests := []struct {
		expr     string
		expected []string
	}{
		{
			"a && b",
			[]string{"->a", "a->b"},
		},
		{
			"a || b",
			[]string{"->a", "->b"},
		},
		{
			"a && b && c",
			[]string{"->a", "a->b", "b->c"},
		},
		{
			"a || b || c",
			[]string{"->a", "->b", "->c"},
		},
		{
			"a && b || c",
			[]string{"->a", "a->b", "->c"},
		},
		{
			"a || b && c",
			[]string{"->a", "->b", "b->c"},
		},
		{
			"(a || b) && (c || d)",
			[]string{"->a", "->b", "a->c", "a->d", "b->c", "b->d"},
		},
		{
			"(a || b && c) && (d || f)",
			[]string{"->a", "->b", "b->c", "a->d", "a->f", "c->d", "c->f"},
		},
		{
			"(a || b) == (d || f)",
			[]string{"->(a || b) == (d || f)"},
		},
		{
			"fn(a) && b",
			[]string{"->fn(a)", "fn(a)->b"},
		},
		{
			"unknown(a)", //unknown function
			nil,
		},
		{
			"foo.x", //private property
			nil,
		},
	}

	treeToList := func(root *MatcherStage) []string {
		res := []string{}
		q := []*MatcherStage{root}
		for len(q) > 0 {
			node := q[0]
			q = q[1:]
			q = append(q, node.children...)

			for _, child := range node.children {
				res = append(res, fmt.Sprintf("%s->%s", node.expr, child.expr))
			}
		}
		return res
	}

	fns := map[string]govaluate.ExpressionFunction{
		"fn": func(arguments ...interface{}) (interface{}, error) { return nil, nil },
	}

	for _, test := range tests {
		def := NewMatcherDef("", test.expr)

		err := def.Build(fns)
		if err != nil {
			if test.expected == nil {
				continue
			}
			t.Error(err.Error())
		}

		assert.ElementsMatch(t, test.expected, treeToList(def.root), test.expr)
	}

}

func TestTokensToExpr(t *testing.T) {

	tests := []string{
		"0",
		"true",
		"false",
		"'foo'",
		"1 + 2 - 3 / 4 * 5",
		"a & b",
		"a | b",
		"2 > 1",
		"1 < 2",
		"a == b",
		"foo.X",
		"foo.Bar.Baz()",
		"!true",
		"(a || b && c) && (d || f)",
		"a == b ? true : false",
		"fn()",
		"fn(1, 2, 3)",
	}

	fns := map[string]govaluate.ExpressionFunction{
		"fn": func(arguments ...interface{}) (interface{}, error) { return nil, nil },
	}

	for _, expr := range tests {
		parsedExpr, err := govaluate.NewEvaluableExpressionWithFunctions(expr, fns)
		if err != nil {
			t.Error(err.Error())
		}
		tokens := parsedExpr.Tokens()
		assert.Equal(t, expr, tokensToExpr(tokens), expr)
	}

}

func TestToString(t *testing.T) {
	tests := []struct {
		key   string
		value string
	}{
		{"r", "sub, obj, act"},
		{"r2", "dom, sub, obj, act"},
		{"p", "sub, obj, act"},
		{"p2", "sub, obj, act, eft"},
		{"g", "_,_"},
		{"g", "_,_,_"},
		{"e", eft.SOME_ALLOW},
		{"m", "true"},
		{"m2", "p.obj == r.obj && p.sub == r.sub"},
		{"m3", "p5.obj == r3.obj"},
	}

	for _, test := range tests {

		var def IDef
		switch test.key[0] {
		case 'r':
			def = NewRequestDef(test.key, test.value)
		case 'p':
			def = NewPolicyDef(test.key, test.value)
		case 'g':
			def = NewRoleDef(test.key, test.value)
		case 'e':
			def = NewEffectDef(test.key, test.value)
		case 'm':
			def = NewMatcherDef(test.key, test.value)
		}

		expected := fmt.Sprintf("%s = %s", test.key, test.value)
		assert.Equal(t, expected, def.String())
		assert.Equal(t, test.key, def.GetKey())
	}
}

func TestPolicyDef(t *testing.T) {

	tests := []struct {
		key   string
		value string
	}{
		{"p", "sub, obj, act"},
		{"p2", "sub, obj, act, eft"},
	}

	for i, test := range tests {

		def := NewPolicyDef(test.key, test.value)

		t.Run("GetArgs", func(t *testing.T) {

			expected := [][]string{
				{"sub", "obj", "act"},
				{"sub", "obj", "act", "eft"},
			}

			assert.ElementsMatch(t, expected[i], def.GetArgs())
		})

		t.Run("GetEft", func(t *testing.T) {

			values := [][][]string{
				{
					{"alice", "data1", "read"},
					{"alice", "data2", "read"},
				},
				{
					{"alice", "data1", "read", "allow"},
					{"alice", "data1", "read", "deny"},
					{"alice", "data1", "read", "foo"},
				},
			}

			rules := values[i]

			expected := [][]types.Effect{
				{
					eft.Allow,
					eft.Allow,
				},
				{
					eft.Allow,
					eft.Deny,
					eft.Indeterminate,
				},
			}

			for j, rule := range rules {
				assert.Equal(t, expected[i][j], def.GetEft(rule))
			}

		})

		t.Run("GetParameters", func(t *testing.T) {

			values := [][][]string{
				{
					{"alice", "data1", "read"},
					{"alice", "data2", "write"},
					{"alice", "data3"},
					{"alice", "data4", "read"},
					{"p", "alice", "data4", "read"},
				},
				{},
			}

			names := [][][]string{
				{
					{"p_obj"},
					{"p_obj", "p_act"},
					{"p_act"},
					{"p_foo"},
					{"p_sub"},
				},
			}

			expected := [][][]string{
				{
					{"data1"},
					{"data2", "write"},
					nil,
					nil,
					{"alice"},
				},
				{},
			}

			for j, exp := range expected[i] {
				res, _ := def.GetParameters(values[i][j], names[i][j])
				assert.Equal(t, exp, res)
			}
		})

	}
}

func TestRequestDef(t *testing.T) {

	tests := []struct {
		key   string
		value string
	}{
		{"r", "sub, obj, act"},
	}

	for i, test := range tests {

		def := NewRequestDef(test.key, test.value)

		t.Run("GetParameters", func(t *testing.T) {

			values := [][][]interface{}{
				{
					{"alice", "data1", "read"},
					{"alice", "data2", "write"},
					{"alice", "data3"},
					{"alice", "data4", "read"},
					{"r", "alice", "data4", "read"},
				},
				{},
			}

			names := [][][]string{
				{
					{"r_obj"},
					{"r_obj", "r_act"},
					{"r_act"},
					{"r_foo"},
					{"r_sub"},
				},
			}

			expected := [][][]interface{}{
				{
					{"data1"},
					{"data2", "write"},
					nil,
					nil,
					{"alice"},
				},
				{},
			}

			for j, exp := range expected[i] {
				res, _ := def.GetParameters(values[i][j], names[i][j])
				assert.Equal(t, exp, res)
			}
		})

	}
}

func TestMatcherDef(t *testing.T) {

	tests := []struct {
		key   string
		value string
	}{
		{"m1", "p.sub == r.sub && p.act == r.act"},
		{"m1", "g.user == r.user || g.role == r.role"},
		{"m2", "r.r.Age > 10"},
		{"m2", "true"},
	}

	for i, test := range tests {

		def := NewMatcherDef(test.key, test.value)
		_ = def.Build(nil)

		t.Run("GetPolicyArgs", func(t *testing.T) {

			expected := [][]string{
				{"p_sub", "p_act"},
				{"g_user", "g_role"},
				{},
				{},
			}

			assert.ElementsMatch(t, expected[i], def.GetPolicyArgs())
		})

		t.Run("Get", func(t *testing.T) {

			expected := [][]string{
				{"r_sub", "r_act"},
				{"r_user", "r_role"},
				{"r_r"},
				{},
			}

			assert.ElementsMatch(t, expected[i], def.GetRequestArgs())
		})

	}
}
