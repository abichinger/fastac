package adapter

import (
	"encoding/csv"
	"strings"

	"example.com/fastac/api"
)

// Adapter is the interface for Casbin adapters.
type Adapter interface {
	// LoadPolicy loads all policy rules from the storage.
	LoadPolicy(model api.IAddRuleBool) error
	// SavePolicy saves all policy rules to the storage.
	SavePolicy(model api.IRangeRules) error
}

type SimpleAdapter interface {
	Adapter

	api.IAddRule
	api.IRemoveRule
}

// type FilteredAdapter interface {
// 	Adapter

// 	// LoadFilteredPolicy loads only policy rules that match the filter.
// 	LoadFilteredPolicy(model *model.Model, filter interface{}) error
// 	// IsFiltered returns true if the loaded policy has been filtered.
// 	IsFiltered() bool
// }

// BatchAdapter is the interface for Casbin adapters with multiple add and remove policy functions.
type BatchAdapter interface {
	Adapter

	api.IAddRules
	api.IRemoveRules
}

// LoadPolicyLine loads a text line as a policy rule to model.
func LoadPolicyLine(line string, m api.IAddRuleBool) {
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

	m.AddRule(tokens)
}
