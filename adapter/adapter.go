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

	// AddPolicy adds a policy rule to the storage.
	// This is part of the Auto-Save feature.
	AddPolicy(sec string, key string, rule []string) error
	// RemovePolicy removes a policy rule from the storage.
	// This is part of the Auto-Save feature.
	RemovePolicy(sec string, key string, rule []string) error
}

type FilteredAdapter interface {
	Adapter

	// LoadFilteredPolicy loads only policy rules that match the filter.
	LoadFilteredPolicy(model *model.Model, filter interface{}) error
	// IsFiltered returns true if the loaded policy has been filtered.
	IsFiltered() bool
}

// BatchAdapter is the interface for Casbin adapters with multiple add and remove policy functions.
type BatchAdapter interface {
	Adapter
	// AddPolicies adds policy rules to the storage.
	// This is part of the Auto-Save feature.
	AddPolicies(sec string, key string, rules [][]string) error
	// RemovePolicies removes policy rules from the storage.
	// This is part of the Auto-Save feature.
	RemovePolicies(sec string, key string, rules [][]string) error
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

	m.AddRule(tokens)
}
