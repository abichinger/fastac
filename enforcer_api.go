package fastac

import (
	"example.com/fastac/adapter"
	"example.com/fastac/model"
)

type IEnforcer interface {
	GetModel() *model.Model
	SetModel(m *model.Model)
	GetAdapter() *adapter.Adapter
	SetAdapter(*adapter.Adapter)

	Enforce(rvals ...interface{}) (bool, error)
	EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error)
	EnforceWithKeys(mKey string, rKey string, eKey string, rvals ...interface{})

	Filter(rvals ...interface{}) (bool, error)
	FilterWithMatcher(matcher string, rvals ...interface{}) (bool, error)
	FilterWithKeys(mKey string, rKey string, rvals ...interface{}) (bool, error)

	AddRule(params ...string) (bool, error)
	RemoveRule(params ...string) (bool, error)
}
