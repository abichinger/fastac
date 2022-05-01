package defs

import (
	"errors"
	"fmt"
	"strings"

	"github.com/abichinger/govaluate"
)

type MatcherStage struct {
	expr     string
	pArgs    []string
	rArgs    []string
	children []*MatcherStage
}

func NewMatcherStage(expr string) *MatcherStage {
	stage := &MatcherStage{}
	stage.expr = expr
	stage.pArgs = pArgReg.FindAllString(stage.expr, -1)
	stage.rArgs = rArgReg.FindAllString(stage.expr, -1)
	return stage
}

func (stage *MatcherStage) GetPolicyArgs() []string {
	return stage.pArgs
}

func (stage *MatcherStage) RecursivePolicyArgs() []string {
	res := []string{}
	res = append(res, stage.GetPolicyArgs()...)
	for _, child := range stage.children {
		res = append(res, child.RecursivePolicyArgs()...)
	}
	return res
}

func (stage *MatcherStage) GetRequestArgs() []string {
	return stage.rArgs
}

func (stage *MatcherStage) RecursiveRequestArgs() []string {
	res := []string{}
	res = append(res, stage.rArgs...)
	for _, child := range stage.children {
		res = append(res, child.RecursiveRequestArgs()...)
	}
	return res
}

func (stage *MatcherStage) Children() []*MatcherStage {
	return stage.children
}

func (stage *MatcherStage) IsLeafNode() bool {
	return len(stage.children) == 0
}

func (def *MatcherStage) NewExpressionWithFunctions(functions map[string]govaluate.ExpressionFunction) (*govaluate.EvaluableExpression, error) {
	return govaluate.NewEvaluableExpressionWithFunctions(def.expr, functions)
}

type MatcherDef struct {
	key  string
	expr string
	root *MatcherStage
}

//nextOperator returns the index of the next logical operator, or -1
func nextOperator(tokens []govaluate.ExpressionToken) (int, bool) {
	clauseCounter := 0
	index := -1
	isBracket := tokens[0].Kind == govaluate.CLAUSE

	for i, token := range tokens {
		switch token.Kind {
		case govaluate.CLAUSE:
			clauseCounter++
		case govaluate.CLAUSE_CLOSE:
			clauseCounter--
			if isBracket && clauseCounter == 0 && i != len(tokens)-1 {
				isBracket = false
			}
		case govaluate.LOGICALOP:
			if clauseCounter != 0 {
				break
			}
			index = i
			if token.Value == "||" {
				return index, false
			}
		}
	}
	return index, isBracket
}

func tokensToExpr(tokens []govaluate.ExpressionToken) string {
	res := ""
	for i, token := range tokens {
		switch token.Kind {
		case govaluate.STRING:
			res += fmt.Sprintf("'%v'", token.Value)
		case govaluate.CLAUSE:
			res += "("
		case govaluate.CLAUSE_CLOSE:
			res += ")"
		case govaluate.ACCESSOR:
			res += strings.Join(token.Value.([]string), ".")
		case govaluate.FUNCTION:
			res += token.Value2.(string)
		default:
			res += fmt.Sprintf("%v", token.Value)
		}

		nextKind := govaluate.UNKNOWN
		if i+1 < len(tokens) {
			nextKind = tokens[i+1].Kind
		}

		switch token.Kind {
		case govaluate.PREFIX, govaluate.CLAUSE, govaluate.FUNCTION:
			break
		case govaluate.ACCESSOR:
			if nextKind == govaluate.CLAUSE {
				break
			}
		default:
			if i != len(tokens)-1 && nextKind != govaluate.CLAUSE_CLOSE && nextKind != govaluate.SEPARATOR {
				res += " "
			}
		}
	}
	return res
}

func buildExprTree(node *MatcherStage, tokens []govaluate.ExpressionToken, and [][]govaluate.ExpressionToken) error {
	index, isBracket := nextOperator(tokens)

	//expr is wrapped inside brackets
	if isBracket {
		return buildExprTree(node, tokens[1:len(tokens)-1], and)
	}

	//expr has no more logical operators
	if index == -1 {
		expr := tokensToExpr(tokens)
		nextNode := NewMatcherStage(expr)
		node.children = append(node.children, nextNode)
		if len(and) > 0 {
			bTokens := and[len(and)-1]
			return buildExprTree(nextNode, bTokens, and[:len(and)-1])
		}
		return nil
	}

	operator := tokens[index]
	if operator.Value == "||" {
		err := buildExprTree(node, tokens[:index], and)
		if err != nil {
			return err
		}
		return buildExprTree(node, tokens[index+1:], and)
	} else { // operator.Value == &&
		return buildExprTree(node, tokens[:index], append(and, tokens[index+1:]))
	}
}

func NewMatcherDef(key string, expr string) *MatcherDef {
	return &MatcherDef{key, expr, nil}
}

func (def *MatcherDef) Build(functions map[string]govaluate.ExpressionFunction) (err error) {
	defer func() {
		if r := recover(); r != nil {
			switch rType := r.(type) {
			case string:
				err = errors.New(rType)
			case error:
				err = rType
			default:
				err = fmt.Errorf("Build failed: %s", def.expr)
			}
		}
	}()

	def.root = NewMatcherStage("")
	expr := ArgReg.ReplaceAllString(def.expr, "${1}_${3}")
	parsedExpr, err := govaluate.NewEvaluableExpressionWithFunctions(expr, functions)
	if err != nil {
		return err
	}
	return buildExprTree(def.root, parsedExpr.Tokens(), nil)
}

func (def *MatcherDef) Root() *MatcherStage {
	return def.root
}

func (def *MatcherDef) GetKey() string {
	return def.key
}

func (def *MatcherDef) GetPolicyArgs() []string {
	return def.root.RecursivePolicyArgs()
}

func (def *MatcherDef) GetRequestArgs() []string {
	return def.root.RecursiveRequestArgs()
}

func (def *MatcherDef) GetPolicyKey() string {
	pArgs := def.GetPolicyArgs()
	pKey := "p"
	if len(pArgs) > 0 {
		pKey = strings.Split(pArgs[0], "_")[0]
	}
	return pKey
}

func (def *MatcherDef) String() string {
	return fmt.Sprintf("%s = %s", def.key, def.expr)

}
