package fastac

import (
	"fmt"

	"github.com/abichinger/fastac/model"
	"github.com/abichinger/fastac/model/defs"
	e "github.com/abichinger/fastac/model/effector"
	m "github.com/abichinger/fastac/model/matcher"
	"github.com/abichinger/fastac/str"
)

type ContextOption func(ctx *Context) error

func SetMatcher(matcher interface{}) ContextOption {
	return func(ctx *Context) error {
		var err error
		switch mType := matcher.(type) {
		case string:
			if mType == "" {
				break
			}
			m, ok := ctx.model.GetMatcher(mType)
			if !ok {
				mDef := defs.NewMatcherDef("", mType)
				m, err = ctx.model.BuildMatcherFromDef(mDef)
				if err != nil {
					return err
				}
			}
			ctx.matcher = m
		case *defs.MatcherDef:
			m, err := ctx.model.BuildMatcherFromDef(mType)
			if err != nil {
				return err
			}
			ctx.matcher = m
		case m.IMatcher:
			ctx.matcher = mType
		}
		return nil
	}
}

func SetRequestDef(definition interface{}) ContextOption {
	return func(ctx *Context) error {
		switch rType := definition.(type) {
		case string:
			if rType == "" {
				break
			}
			rDef, ok := ctx.model.GetRequestDef(rType)
			if !ok {
				return fmt.Errorf(str.ERR_REQUESTDEF_NOT_FOUND, rType)
			}
			ctx.rDef = rDef
		case *defs.RequestDef:
			ctx.rDef = rType
		}
		return nil
	}
}

func SetEffector(effector interface{}) ContextOption {
	return func(ctx *Context) error {
		switch eType := effector.(type) {
		case string:
			if eType == "" {
				break
			}
			eff, ok := ctx.model.GetEffector(eType)
			if !ok {
				eDef := defs.NewEffectDef("", eType)
				eff = e.NewEffector(eDef)
			}
			ctx.effector = eff
		case *defs.EffectDef:
			eff := e.NewEffector(eType)
			ctx.effector = eff
		case e.IEffector:
			ctx.effector = eType
		}
		return nil
	}
}

type Context struct {
	model model.IModel

	rDef     *defs.RequestDef
	matcher  m.IMatcher
	effector e.IEffector
}

func NewContext(model model.IModel, options ...ContextOption) (*Context, error) {
	ctx := &Context{}
	ctx.model = model

	for _, option := range options {
		if err := option(ctx); err != nil {
			return nil, err
		}
	}

	if ctx.rDef == nil {
		_ = SetRequestDef("r")(ctx)
	}
	if ctx.matcher == nil {
		_ = SetMatcher("m")(ctx)
	}
	if ctx.effector == nil {
		_ = SetEffector("e")(ctx)
	}

	return ctx, nil
}
