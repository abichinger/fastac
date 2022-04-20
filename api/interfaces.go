package api

import em "github.com/vansante/go-event-emitter"

type IAddRule interface {
	AddRule(rule []string) error
}

type IAddRuleBool interface {
	AddRule(rule []string) (bool, error)
}

type IAddRules interface {
	AddRules(rules [][]string) error
}

type IRemoveRule interface {
	RemoveRule(rule []string) error
}

type IRemoveRuleBool interface {
	RemoveRule(rule []string) (bool, error)
}

type IRemoveRules interface {
	RemoveRules(rule [][]string) error
}

type IAddListener interface {
	AddListener(event em.EventType, handler em.HandleFunc) (listener *em.Listener)
}

type IRemoveListener interface {
	RemoveListener(event em.EventType, listener *em.Listener)
}

type IAddRemoveListener interface {
	IAddListener
	IRemoveListener
}

type IRangeRules interface {
	RangeRules(fn func(rule []string) bool)
}
