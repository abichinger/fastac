package fastac

type EnforcerAPI interface {
	//enforce(matchers []MatcherDef, rvals ...interface{}) (ok bool, err error)

	Enforce(rvals ...interface{}) (bool, error)
	EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error)
	EnforceWithMatchers(matchers []string, rvals ...interface{}) (bool, error)

	FilterWithMatcher(matcher string, rvals ...interface{}) (bool, error)
	FilterWithMatchers(matchers []string, rvals ...interface{}) (bool, error)

	RangeWithMatcher(matcher string, rvals ...interface{}) (bool, error)
	RangeWithMatchers(matchers []string, rvals ...interface{}) (bool, error)
}
