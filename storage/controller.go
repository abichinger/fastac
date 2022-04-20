package storage

import (
	"example.com/fastac/api"
	"example.com/fastac/model"
	"example.com/fastac/storage/adapter"
	eventemitter "github.com/vansante/go-event-emitter"
)

type opcode int

const (
	add opcode = iota
	remove
)

type operation struct {
	opc  opcode
	rule []string
}

type listener struct {
	event    eventemitter.EventType
	listener *eventemitter.Listener
}

type StorageController struct {
	autosave  bool
	em        api.IAddRemoveListener
	adapter   adapter.Adapter
	q         []operation
	wait      int
	listeners []listener
}

func NewStorageController(eventemitter api.IAddRemoveListener, adapter adapter.Adapter, autosave bool) *StorageController {
	sc := &StorageController{
		em:        eventemitter,
		adapter:   adapter,
		autosave:  autosave,
		listeners: []listener{},
	}

	sc.Enable()

	return sc
}

func (sc *StorageController) addListener(event eventemitter.EventType, opc opcode) {
	l := sc.em.AddListener(event, func(arguments ...interface{}) {
		rule := arguments[0].([]string)
		sc.addOp(opc, rule)
	})

	sc.listeners = append(sc.listeners, listener{event, l})
}

func (sc *StorageController) Enable() {

	if len(sc.listeners) > 0 {
		return
	}

	listenerParams := []struct {
		evt eventemitter.EventType
		opc opcode
	}{
		{model.RULE_ADDED, add},
		{model.RULE_REMOVED, remove},
	}

	for _, params := range listenerParams {
		sc.addListener(params.evt, params.opc)
	}
}

func (sc *StorageController) Disable() {
	for _, listener := range sc.listeners {
		sc.em.RemoveListener(listener.event, listener.listener)
	}
	sc.listeners = []listener{}
}

func (sc *StorageController) addOp(opc opcode, rule []string) {
	sc.q = append(sc.q, operation{opc, rule})
	if sc.autosave {
		sc.wait--
		if sc.wait <= 0 {
			sc.Flush()
		}
	}
}

func (sc *StorageController) EnableAutosave() {
	sc.autosave = true
}

func (sc *StorageController) DisableAutosave() {
	sc.autosave = false
}

func (sc *StorageController) flush() {
	for len(sc.q) > 0 {
		operation := sc.q[0]
		sc.q = sc.q[1:]
		sc.run(operation.opc, operation.rule)
	}
}

func (sc *StorageController) batchFlush() {

	rules := [][]string{}

	var currentOpc opcode
	if len(sc.q) > 0 {
		currentOpc = sc.q[0].opc
	}

	for len(sc.q) > 0 {

		operation := sc.q[0]
		sc.q = sc.q[1:]

		if currentOpc == operation.opc {
			rules = append(rules, operation.rule)
		} else {
			sc.runBatch(currentOpc, rules)
			currentOpc = operation.opc
			rules = [][]string{operation.rule}
		}
	}

	if len(rules) > 0 {
		sc.runBatch(currentOpc, rules)
	}
}

func (sc *StorageController) Flush() {
	switch sc.adapter.(type) {
	case adapter.BatchAdapter:
		sc.batchFlush()
		break
	case adapter.SimpleAdapter:
		sc.flush()
		break
	default:
		panic("invalid adapter")
	}

	sc.wait = 0
}

func (sc *StorageController) run(opc opcode, rule []string) {
	adapter := sc.adapter.(adapter.SimpleAdapter)

	switch opc {
	case add:
		adapter.AddRule(rule)
		break
	case remove:
		adapter.RemoveRule(rule)
		break
	}
}

func (sc *StorageController) runBatch(opc opcode, rules [][]string) {
	adapter := sc.adapter.(adapter.BatchAdapter)

	switch opc {
	case add:
		adapter.AddRules(rules)
		break
	case remove:
		adapter.RemoveRules(rules)
		break
	}
}

func (sc *StorageController) AddWait(i int) {
	sc.wait += i
}
