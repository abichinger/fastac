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

package matcher

import (
	"errors"
	"fmt"

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
	case 'p', 'g':
		return params.pDef.GetParameter(params.pvals, name)
	case 'r':
		return params.rDef.GetParameter(params.rvals, name)
	default:
		return nil, errors.New("No parameter '" + name + "' found.")
	}
}

type Matcher struct {
	matchers []*defs.MatcherStage
	pDef     *defs.PolicyDef
	policy   p.IPolicy
	root     *MatcherNode
}

func NewMatcher(pDef *defs.PolicyDef, policy p.IPolicy, matchers []*defs.MatcherStage) *Matcher {
	m := &Matcher{}
	m.pDef = pDef
	m.policy = policy
	m.matchers = matchers
	m.root = NewMatcherNode([]string{""})

	policy.Range(func(rule []string) bool {
		m.addRule(rule)
		return true
	})

	policy.AddListener(p.EVT_RULE_ADDED, func(arguments ...interface{}) {
		rule := arguments[0].([]string)
		m.addRule(rule)
	})

	policy.AddListener(p.EVT_RULE_REMOVED, func(arguments ...interface{}) {
		rule := arguments[0].([]string)
		m.removeRule(rule)
	})

	policy.AddListener(p.EVT_CLEARED, func(arguments ...interface{}) {
		m.root = NewMatcherNode([]string{""})
	})

	return m
}

func (m *Matcher) GetPolicyKey() string {
	return m.pDef.GetKey()
}

func (m *Matcher) addRule(rule types.Rule) {
	m.addRuleHelper(rule, 0, m.root)
}

func (m *Matcher) addRuleHelper(rule types.Rule, level int, node *MatcherNode) {
	pArgs := m.matchers[level].GetPolicyArgs()
	if len(pArgs) == 0 {
		return
	}

	if level < len(m.matchers)-1 {
		key, _ := m.pDef.GetParameters(rule, pArgs)
		nextNode := node.GetOrCreate(key, rule)
		m.addRuleHelper(rule, level+1, nextNode)
	} else {
		hash := rule.Hash()
		node.children[hash] = NewMatcherNode(rule)
	}
}

func (m *Matcher) removeRule(rule types.Rule) {
	m.removeRuleHelper(rule, 0, m.root)
}

func (m *Matcher) removeRuleHelper(rule types.Rule, level int, node *MatcherNode) {
	pArgs := m.matchers[level].GetPolicyArgs()
	if len(pArgs) == 0 {
		return
	}

	if level < len(m.matchers)-1 {
		key, _ := m.pDef.GetParameters(rule, pArgs)
		strKey := key.Hash()
		if nextNode, ok := node.children[strKey]; ok {
			m.removeRuleHelper(rule, level+1, nextNode)
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

	params := NewMatchParameters(*m.pDef, nil, rDef, rvals)
	fMap.SetFunction("eval", generateEvalFunction(fMap, params))
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
			params.pvals = make(types.Rule, len(m.pDef.GetArgs()))
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
