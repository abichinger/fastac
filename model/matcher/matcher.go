package matcher

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/fm"
	p "github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/model/types"
	"github.com/abichinger/fastac/util"
)

type MatcherNode struct {
	rule     types.Rule
	children map[string]*MatcherNode
}

func NewMatcherNode(rule types.Rule) *MatcherNode {
	node := &MatcherNode{}
	node.rule = rule
	node.children = make(map[string]*MatcherNode)
	return node
}

func (n *MatcherNode) GetOrCreate(key types.Rule, rule types.Rule) *MatcherNode {
	strKey := key.Hash()
	if node, ok := n.children[strKey]; ok {
		return node
	}
	node := NewMatcherNode(rule)
	n.children[strKey] = node
	return node
}

type MatchParameters struct {
	pDef  defs.PolicyDef
	pvals types.Rule
	rDef  defs.RequestDef
	rvals []interface{}
}

func NewMatchParameters(pDef defs.PolicyDef, pvals types.Rule, rDef defs.RequestDef, rvals []interface{}) *MatchParameters {
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
	matchers []*defs.MatcherDef
	policy   *p.Policy
	root     *MatcherNode
}

func NewMatcher(policy *p.Policy, matchers []*defs.MatcherDef) *Matcher {
	m := &Matcher{}
	m.policy = policy
	m.matchers = matchers
	m.root = NewMatcherNode([]string{""})

	policy.Range(func(hash string, rule types.Rule) bool {
		m.AddPolicy(rule)
		return true
	})

	policy.AddListener(p.PolicyAdded, func(arguments ...interface{}) {
		rule := arguments[0].(types.Rule)
		m.AddPolicy(rule)
	})

	policy.AddListener(p.PolicyRemoved, func(arguments ...interface{}) {
		rule := arguments[0].(types.Rule)
		m.RemovePolicy(rule)
	})

	return m
}

func (m *Matcher) GetPolicy() *p.Policy {
	return m.policy
}

func (m *Matcher) AddPolicy(rule types.Rule) {
	m.addPolicy(rule, 0, m.root)
}

func (m *Matcher) addPolicy(rule types.Rule, level int, node *MatcherNode) {
	pArgs := m.matchers[level].GetPolicyArgs()
	if len(pArgs) == 0 {
		return
	}

	if level < len(m.matchers)-1 {
		key, _ := m.policy.GetParameters(rule, pArgs)
		nextNode := node.GetOrCreate(key, rule)
		m.addPolicy(rule, level+1, nextNode)
	} else {
		hash := rule.Hash()
		node.children[hash] = NewMatcherNode(rule)
	}
}

func (m *Matcher) RemovePolicy(rule types.Rule) {
	m.removePolicy(rule, 0, m.root)
}

func (m *Matcher) removePolicy(rule types.Rule, level int, node *MatcherNode) {
	pArgs := m.matchers[level].GetPolicyArgs()
	if len(pArgs) == 0 {
		return
	}

	if level < len(m.matchers)-1 {
		key, _ := m.policy.GetParameters(rule, pArgs)
		strKey := key.Hash()
		if nextNode, ok := node.children[strKey]; ok {
			m.removePolicy(rule, level+1, nextNode)
		}
	} else {
		hash := rule.Hash()
		delete(node.children, hash)
	}
}

func (m *Matcher) RangeMatches(rDef defs.RequestDef, rvals []interface{}, fMap fm.FunctionMap, fn func(rule types.Rule) bool) error {
	level := 0
	q := make([]*MatcherNode, 0)
	q = append(q, m.root)
	empty := true

	params := NewMatchParameters(*m.policy.PolicyDef, nil, rDef, rvals)
	fMap.AddFunction("eval", generateEvalFunction(fMap, params))
	functions := fMap.GetFunctions()

	for len(q) > 0 {
		levelSize := len(q)

		expr, err := m.matchers[level].NewExpressionWithFunctions(functions)
		if err != nil {
			return err
		}

		if level < len(m.matchers) {

			for levelSize > 0 {
				node := q[0]
				q = q[1:]
				levelSize--

				for _, child := range node.children {
					if level == len(m.matchers)-1 {
						empty = false
					}
					params.pvals = child.rule
					res, err := expr.Eval(params)
					if err != nil {
						return err
					}
					if res.(bool) {
						if level < len(m.matchers)-1 {
							q = append(q, child)
						} else {
							if !fn(child.rule) {
								return nil
							}
						}
					}
				}
			}
		}

		if empty && level == len(m.matchers)-1 {
			params.pvals = make(types.Rule, len(m.policy.GetArgs()))
			res, err := expr.Eval(params)
			if err != nil {
				return err
			}
			if res.(bool) {
				fn(params.pvals)
			}
		}

		level++
	}
	return nil
}

func (m *Matcher) String() string {
	res := []string{}
	for _, mDef := range m.matchers {
		res = append(res, mDef.String())
	}
	return strings.Join(res, "\n")
}

func eval(expression string, functions map[string]govaluate.ExpressionFunction, parameters *MatchParameters) (interface{}, error) {
	expr, err := govaluate.NewEvaluableExpressionWithFunctions(expression, functions)
	if err != nil {
		return nil, err
	}
	return expr.Eval(parameters)
}

func generateEvalFunction(fMap fm.FunctionMap, parameters *MatchParameters) govaluate.ExpressionFunction {
	functions := fMap.GetFunctions()

	return func(args ...interface{}) (interface{}, error) {
		if err := util.ValidateVariadicArgs(1, args...); err != nil {
			return false, fmt.Errorf("%s: %s", "eval", err)
		}

		expression := args[0].(string)
		expression = defs.ArgReg.ReplaceAllString(expression, "${1}_${3}")
		return eval(expression, functions, parameters)
	}
}
