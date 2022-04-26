package policy

import (
	"github.com/abichinger/fastac/api"
	"github.com/abichinger/fastac/util"
	em "github.com/vansante/go-event-emitter"
)

const (
	EVT_RULE_ADDED   em.EventType = "rule_added"
	EVT_RULE_REMOVED em.EventType = "rule_removed"
	EVT_CLEARED      em.EventType = "cleared"
)

type IPolicy interface {
	api.IAddRuleBool
	api.IRemoveRuleBool
	api.IAddRemoveListener
	api.IClear

	Range(fn func(rule []string) bool)
}

func GetDistinct(p IPolicy, columns []int) ([][]string, error) {
	resMap := make(map[string][]string)
	p.Range(func(rule []string) bool {
		values := make([]string, len(columns))
		for i, column := range columns {
			values[i] = rule[column]
		}
		resMap[util.Hash(values)] = values
		return true
	})
	res := make([][]string, 0)
	for _, values := range resMap {
		res = append(res, values)
	}
	return res, nil
}
