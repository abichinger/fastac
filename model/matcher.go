package model

import (
	"errors"
	"fmt"

	"example.com/fastac/util"
	"github.com/Knetic/govaluate"
)

type MatcherNode struct {
	rule     Rule
	children map[string]*MatcherNode
	policies []Rule
}

func NewMatcherNode(rule Rule) *MatcherNode {
	node := &MatcherNode{}
	node.rule = rule
	node.children = make(map[string]*MatcherNode)
	node.policies = make([]Rule, 0)
	return node
}

func (n *MatcherNode) GetOrCreate(key Rule, rule Rule) *MatcherNode {
	strKey := key.Hash()
	if node, ok := n.children[strKey]; ok {
		return node
	}
	node := NewMatcherNode(rule)
	n.children[strKey] = node
	return node
}

type MatchParameters struct {
	pDef  PolicyDef
	pvals Rule
	rDef  RequestDef
	rvals []interface{}
}

func NewMatchParameters(pDef PolicyDef, pvals Rule, rDef RequestDef, rvals []interface{}) *MatchParameters {
	return &MatchParameters{
		pDef:  pDef,
		pvals: pvals,
		rDef:  rDef,
		rvals: rvals,
	}
}

func (params *MatchParameters) Get(name string) (interface{}, error) {
	switch name[0] {
	case 'p':
		return params.pDef.GetParameter(params.pvals, name)
	case 'r':
		return params.rDef.GetParameter(params.rvals, name)
	default:
		return nil, errors.New("No parameter '" + name + "' found.")
	}
}

type Matcher struct {
	matchers []*MatcherDef
	policy   *Policy
	root     *MatcherNode
}

func NewMatcher(policy *Policy, matchers []*MatcherDef) *Matcher {
	m := &Matcher{}
	m.policy = policy
	m.matchers = matchers
	m.root = NewMatcherNode([]string{""})

	policy.Range(func(i int, rule Rule) bool {
		m.AddPolicy(rule)
		return false
	})

	policy.AddListener(PolicyAdded, func(arguments ...interface{}) {
		rule := arguments[0].(Rule)
		m.AddPolicy(rule)
	})

	policy.AddListener(PolicyRemoved, func(arguments ...interface{}) {
		rule := arguments[0].(Rule)
		m.RemovePolicy(rule)
	})

	return m
}

func (m *Matcher) AddPolicy(rule Rule) {
	m.addPolicy(rule, 0, m.root)
}

func (m *Matcher) addPolicy(rule Rule, level int, node *MatcherNode) {
	if level < len(m.matchers)-1 {
		pArgs := m.matchers[level].GetPolicyArgs()
		key, _ := m.policy.GetParameters(rule, pArgs)
		nextNode := node.GetOrCreate(key, rule)
		m.addPolicy(rule, level+1, nextNode)
	} else {
		node.policies = append(node.policies, rule)
	}
}

func (m *Matcher) RemovePolicy(rule Rule) {

}

func (m *Matcher) RangeMatches(rDef RequestDef, rvals []interface{}, fm FunctionMap, fn func(rule Rule) bool) error {
	level := 0
	q := make([]*MatcherNode, 0)
	q = append(q, m.root)

	params := NewMatchParameters(*m.policy.PolicyDef, nil, rDef, rvals)
	fm.AddFunction("eval", GenerateEvalFunction(fm, params))
	functions := fm.GetFunctions()

	for len(q) > 0 {
		levelSize := len(q)

		expr, err := m.matchers[level].NewExpressionWithFunctions(functions, nil)
		if err != nil {
			return err
		}

		if level < len(m.matchers)-1 {

			for levelSize > 0 {
				node := q[0]
				q = q[1:]
				levelSize--

				for _, child := range node.children {
					params.pvals = child.rule
					res, err := expr.Eval(params)
					if err != nil {
						return err
					}
					if res.(bool) {
						q = append(q, child)
					}
				}
			}

		} else {

			for _, node := range q {

				policies := node.policies
				if len(policies) == 0 {
					policies = make([]Rule, 0)
					policies = append(policies, make(Rule, len(params.pDef.args)))
				}

				for _, rule := range policies {
					params.pvals = rule
					res, err := expr.Eval(params)
					if err != nil {
						return err
					}
					if res.(bool) {
						if fn(rule) {
							return nil
						}
					}
				}
			}

			break

		}

		level++
	}
	return nil
}

func eval(expression string, functions map[string]govaluate.ExpressionFunction, parameters *MatchParameters) (interface{}, error) {
	expr, err := govaluate.NewEvaluableExpressionWithFunctions(expression, functions)
	if err != nil {
		return nil, err
	}
	return expr.Eval(parameters)
}

func GenerateEvalFunction(fm FunctionMap, parameters *MatchParameters) govaluate.ExpressionFunction {
	functions := fm.GetFunctions()

	return func(args ...interface{}) (interface{}, error) {
		if err := util.ValidateVariadicArgs(1, args...); err != nil {
			return false, fmt.Errorf("%s: %s", "eval", err)
		}

		expression := args[0].(string)
		expression = argReg.ReplaceAllString(expression, "${1}_${3}")
		return eval(expression, functions, parameters)
	}
}
