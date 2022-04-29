package defs

import (
	"fmt"
	"testing"

	"github.com/abichinger/govaluate"
	"github.com/stretchr/testify/assert"
)

func TestBuildExprTree(t *testing.T) {

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
		root := NewMatcherStage("")
		parsedExpr, err := govaluate.NewEvaluableExpressionWithFunctions(test.expr, fns)
		if err != nil {
			t.Error(err.Error())
		}

		tokens := parsedExpr.Tokens()
		err = buildExprTree(root, tokens, nil)
		if err != nil {
			t.Error(err.Error())
		}

		assert.ElementsMatch(t, test.expected, treeToList(root), test.expr)
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
