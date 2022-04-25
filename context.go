package fastac

import (
	"github.com/abichinger/fastac/model"
	"github.com/abichinger/fastac/model/defs"
	e "github.com/abichinger/fastac/model/effector"
	m "github.com/abichinger/fastac/model/matcher"
)

type ContextOption func(ctx *Context) error

func SetMatcher(matcher interface{}) ContextOption {
	return func(ctx *Context) error {
		var err error

		switch mType := matcher.(type) {
		case string:
			m, ok := ctx.model.GetMatcher(mType)
			if !ok {
				mDef := defs.NewMatcherDef("")
				mDef.AddStage(-1, mType)
				m, err = ctx.model.BuildMatcherFromDef(mDef)
				if err != nil {
					return err
				}
			}
			ctx.matcher = m
		case []string:
			mDef := defs.NewMatcherDef("")
			for i, expr := range mType {
				mDef.AddStage(i, expr)
			}

			m, err := ctx.model.BuildMatcherFromDef(mDef)
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
			rDef, ok := ctx.model.GetRequestDef(rType)
			if !ok {
				rDef = defs.NewRequestDef("", rType)
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
			eff, ok := ctx.model.GetEffector(eType)
			if !ok {
				eDef := defs.NewEffectDef("", eType)
				eff = e.NewEffector(eDef)
			}
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

func NewContext(model model.IModel, options []ContextOption) (*Context, error) {
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
