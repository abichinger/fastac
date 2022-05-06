package log

import (
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

var defaultLogger log.FieldLogger

func NullLogger() log.FieldLogger {
	log := log.New()
	log.SetOutput(ioutil.Discard)
	return log
}

func SetLogger(logger log.FieldLogger) {
	defaultLogger = logger
}

func Logger() log.FieldLogger {
	if defaultLogger == nil {
		SetLogger(NullLogger())
	}
	return defaultLogger
}
