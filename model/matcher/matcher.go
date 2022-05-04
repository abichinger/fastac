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

	"github.com/abichinger/fastac/model/defs"
	"github.com/abichinger/fastac/model/fm"
	p "github.com/abichinger/fastac/model/policy"
	"github.com/abichinger/fastac/util"
	"github.com/abichinger/govaluate"
)

type MatcherNode struct {
	rule     []string
	children []map[string]*MatcherNode
}

func NewMatcherNode(rule []string) *MatcherNode {
	node := &MatcherNode{}
	node.rule = rule
	node.children = make([]map[string]*MatcherNode, 2)
	node.children[0] = make(map[string]*MatcherNode)
	node.children[1] = make(map[string]*MatcherNode)
	return node
}

func (n *MatcherNode) GetOrCreate(i int, key string, rule []string) *MatcherNode {
	if node, ok := n.children[i][key]; ok {
		return node
	}
	node := NewMatcherNode(rule)
	n.children[i][key] = node
	return node
}

type MatchParameters struct {
	pDef  defs.PolicyDef
	pvals []string
	rDef  defs.RequestDef
	rvals []interface{}
}

func NewMatchParameters(pDef defs.PolicyDef, pvals []string, rDef defs.RequestDef, rvals []interface{}) *MatchParameters {
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
	exprRoot *defs.MatcherStage
	pDef     *defs.PolicyDef
	policy   p.IPolicy
	root     *MatcherNode
}

func NewMatcher(pDef *defs.PolicyDef, policy p.IPolicy, exprRoot *defs.MatcherStage) *Matcher {
	m := &Matcher{}
	m.pDef = pDef
	m.policy = policy
	m.exprRoot = exprRoot
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

func (m *Matcher) addRule(rule []string) {
	m.addRuleHelper(rule, m.exprRoot, m.root)
}

func (m *Matcher) addRuleHelper(rule []string, exprNode *defs.MatcherStage, node *MatcherNode) {
	for i, nextExpr := range exprNode.Children() {
		pArgs := nextExpr.GetPolicyArgs()

		var key string
		if len(pArgs) == 0 || nextExpr.IsLeafNode() {
			key = util.Hash(rule)
		} else {
			r, _ := m.pDef.GetParameters(rule, pArgs)
			key = util.Hash(r)
		}

		if !nextExpr.IsLeafNode() {
			nextNode := node.GetOrCreate(i, key, rule)
			m.addRuleHelper(rule, nextExpr, nextNode)
		} else {
			node.children[i][key] = NewMatcherNode(rule)
		}
	}

}

func (m *Matcher) removeRule(rule []string) {
	m.removeRuleHelper(rule, m.exprRoot, m.root)
}

func (m *Matcher) removeRuleHelper(rule []string, exprNode *defs.MatcherStage, node *MatcherNode) {
	for i, nextExpr := range exprNode.Children() {
		pArgs := nextExpr.GetPolicyArgs()

		var key string
		if len(pArgs) == 0 || nextExpr.IsLeafNode() {
			key = util.Hash(rule)
		} else {
			r, _ := m.pDef.GetParameters(rule, pArgs)
			key = util.Hash(r)
		}

		if !nextExpr.IsLeafNode() {
			if nextNode, ok := node.children[i][key]; ok {
				m.removeRuleHelper(rule, nextExpr, nextNode)
			}
		} else {
			delete(node.children[i], key)
		}
	}
}

func (m *Matcher) rangeMatches(exprNode *defs.MatcherStage, rules map[string]*MatcherNode, params *MatchParameters, functions map[string]govaluate.ExpressionFunction, fn func(node *MatcherNode) bool) (bool, error) {
	expr, err := exprNode.NewExpressionWithFunctions(functions)
	if err != nil {
		return false, err
	}

	if len(rules) == 0 {
		empty_rule := make([]string, len(m.pDef.GetArgs()))
		rules = map[string]*MatcherNode{
			"": NewMatcherNode(empty_rule),
		}
	}

	for _, child := range rules {
		params.pvals = child.rule
		res, err := expr.Eval(params)
		if err != nil {
			return false, err
		}
		switch b := res.(type) {
		case bool:
			if b && !fn(child) {
				return false, nil
			}
		}
	}
	return true, nil
}

func (m *Matcher) rangeMatchesHelper(exprNode *defs.MatcherStage, node *MatcherNode, params *MatchParameters, functions map[string]govaluate.ExpressionFunction, fn func(rule []string) bool) (bool, error) {
	for i, nextExpr := range exprNode.Children() {
		cont, err := m.rangeMatches(nextExpr, node.children[i], params, functions, func(nextNode *MatcherNode) bool {
			if nextExpr.IsLeafNode() && !fn(nextNode.rule) {
				return false //break
			} else {
				cont, err := m.rangeMatchesHelper(nextExpr, nextNode, params, functions, fn)
				if err != nil || !cont {
					return false
				}
			}
			return true //continue
		})
		if err != nil {
			return false, err
		}
		if !cont {
			return false, nil
		}
	}
	return true, nil
}

func (m *Matcher) RangeMatches(rDef defs.RequestDef, rvals []interface{}, fMap fm.FunctionMap, fn func(rule []string) bool) error {
	params := NewMatchParameters(*m.pDef, nil, rDef, rvals)
	fMap.SetFunction("eval", generateEvalFunction(fMap, params))
	functions := fMap.GetFunctions()

	_, err := m.rangeMatchesHelper(m.exprRoot, m.root, params, functions, fn)
	if err != nil {
		return err
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
