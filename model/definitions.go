package model

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Knetic/govaluate"
)

const DefaultSep = ","
const DefaultRoleParty = "_"

var argReg = regexp.MustCompile(`([pr][0-9]*)(\.|_)([A-Za-z0-9_]+)`)
var pArgReg = regexp.MustCompile(`(p[0-9]*)_([A-Za-z0-9_]+)`)
var rArgReg = regexp.MustCompile(`(r[0-9]*)_([A-Za-z0-9_]+)`)

type PolicyDef struct {
	key      string
	args     []string
	argIndex map[string]int
}

func NewPolicyDef(key, arguments string) *PolicyDef {
	def := &PolicyDef{}
	def.key = key
	def.args = strings.Split(strings.ReplaceAll(arguments, " ", ""), DefaultSep)
	def.argIndex = make(map[string]int, len(def.args))
	for i, arg := range def.args {
		def.argIndex[key+"_"+arg] = i
	}
	return def
}

func (def *PolicyDef) Has(name string) bool {
	_, ok := def.argIndex[name]
	return ok
}

func (def *PolicyDef) GetEft(values []string) Effect {
	eftArg := def.key + "_eft"
	if def.Has(eftArg) {
		eft, _ := def.GetParameter(values, eftArg)
		switch eft {
		case "":
		case "allow":
			return Allow
		case "deny":
			return Deny
		default:
			return Indeterminate
		}
	}
	return Allow
}

func (def *PolicyDef) GetParameter(values []string, name string) (string, error) {
	index, ok := def.argIndex[name]
	if !ok {
		return "", errors.New("No parameter '" + name + "' found.")
	}
	return values[index], nil
}

func (def *PolicyDef) GetParameters(values, names []string) (Rule, error) {
	params := make([]string, 0)
	for _, name := range names {
		value, err := def.GetParameter(values, name)
		if err != nil {
			return nil, err
		}
		params = append(params, value)
	}
	return params, nil
}

func (def *PolicyDef) String() string {
	return fmt.Sprintf("%s = %s", def.key, strings.Join(def.args, DefaultSep+" "))
}

type RequestDef struct {
	key      string
	args     []string
	argIndex map[string]int
}

func NewRequestDef(key, arguments string) *RequestDef {
	def := &RequestDef{}
	def.key = key
	def.args = strings.Split(strings.ReplaceAll(arguments, " ", ""), DefaultSep)
	def.argIndex = make(map[string]int, len(def.args))
	for i, arg := range def.args {
		def.argIndex[key+"_"+arg] = i
	}
	return def
}

func (def *RequestDef) Has(name string) bool {
	_, ok := def.argIndex[name]
	return ok
}

func (def *RequestDef) GetParameter(values []interface{}, name string) (interface{}, error) {
	index, ok := def.argIndex[name]
	if !ok {
		return "", errors.New("No parameter '" + name + "' found.")
	}
	return values[index], nil
}

func (def *RequestDef) GetParameters(values []interface{}, names []string) ([]interface{}, error) {
	params := make([]interface{}, 0)
	for _, name := range names {
		value, err := def.GetParameter(values, name)
		if err != nil {
			return nil, err
		}
		params = append(params, value)
	}
	return params, nil
}

func (def *RequestDef) String() string {
	return fmt.Sprintf("%s = %s", def.key, strings.Join(def.args, DefaultSep+" "))
}

type MatcherDef struct {
	key          string
	index        int
	expr         string
	ruleNames    []string
	exprTemplate string
	pArgs        []string
	rArgs        []string
}

func NewMatcherDef(key, expr string) *MatcherDef {
	def := &MatcherDef{}

	split := strings.Split(key, ".")
	if len(split) <= 1 {
		def.key = key
		def.index = -1
	} else {
		def.key = split[0]
		def.index, _ = strconv.Atoi(split[1])
	}

	def.expr = argReg.ReplaceAllString(expr, "${1}_${3}")
	def.pArgs = pArgReg.FindAllString(def.expr, -1)
	def.rArgs = rArgReg.FindAllString(def.expr, -1)

	return def
}

func (def *MatcherDef) String() string {
	if def.index == -1 {
		return fmt.Sprintf("%s = %s", def.key, argReg.ReplaceAllString(def.expr, "${1}.${3}"))
	}
	return fmt.Sprintf("%s.%d = %s", def.key, def.index, argReg.ReplaceAllString(def.expr, "${1}.${3}"))
}

func (def *MatcherDef) GetPolicyArgs() []string {
	return def.pArgs
}

func (def *MatcherDef) GetRequestArgs() []string {
	return def.rArgs
}

func (def *MatcherDef) NewExpressionWithFunctions(functions map[string]govaluate.ExpressionFunction) (*govaluate.EvaluableExpression, error) {
	return govaluate.NewEvaluableExpressionWithFunctions(def.expr, functions)
}

type EffectDef struct {
	key  string
	expr string
}

func NewEffectDef(key, expr string) *EffectDef {
	def := &EffectDef{}
	def.key = key
	def.expr = strings.ReplaceAll(expr, " ", "")
	return def
}

func (def *EffectDef) Expr() string {
	return def.expr
}

func (def *EffectDef) String() string {
	return fmt.Sprintf("%s = %s", def.key, def.expr)
}

type RoleDef struct {
	key   string
	nargs int
}

func (def *RoleDef) String() string {
	args := make([]string, def.nargs)
	for i := 0; i < def.nargs; i++ {
		args = append(args, DefaultRoleParty)
	}
	return fmt.Sprintf("%s = %s", def.key, strings.Join(args, DefaultSep))
}

func NewRoleDef(key, arguments string) *RoleDef {
	def := &RoleDef{}
	def.key = key
	def.nargs = len(strings.Split(arguments, DefaultSep))
	return def
}
