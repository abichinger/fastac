package adapter

import (
	"encoding/csv"
	"strings"

	"example.com/fastac/model"
)

// Adapter is the interface for Casbin adapters.
type Adapter interface {
	// LoadPolicy loads all policy rules from the storage.
	LoadPolicy(model *model.Model) error
	// SavePolicy saves all policy rules to the storage.
	SavePolicy(model *model.Model) error
}

// LoadPolicyLine loads a text line as a policy rule to model.
func LoadPolicyLine(line string, m *model.Model) {
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}

	r := csv.NewReader(strings.NewReader(line))
	r.Comma = ','
	r.Comment = '#'
	r.TrimLeadingSpace = true

	tokens, err := r.Read()
	if err != nil {
		return
	}

	LoadPolicyArray(tokens, m)
}

// LoadPolicyArray loads a policy rule to model.
func LoadPolicyArray(rule []string, m *model.Model) {
	key := rule[0]
	sec := key[0]
	switch sec {
	case 'p':
		m.AddPolicyRule(key, rule[1:])
		break
	case 'g':
		m.AddRoleRule(key, rule[1:])
	}
}
