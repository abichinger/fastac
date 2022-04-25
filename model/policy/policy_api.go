package policy

import (
	"github.com/abichinger/fastac/api"
	em "github.com/abichinger/go-event-emitter"
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

	Range(fn func(hash string, rule []string) bool)
}
