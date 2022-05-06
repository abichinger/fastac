package log

import (
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestLog(t *testing.T) {
	nullLogger, hook := logrustest.NewNullLogger()
	SetLogger(nullLogger)

	logger := Logger()

	logger.Info("info")

	assert.Equal(t, 1, len(hook.Entries))
	assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
	assert.Equal(t, "info", hook.LastEntry().Message)

	logger.Warn("warning")

	assert.Equal(t, 2, len(hook.Entries))
	assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
	assert.Equal(t, "warning", hook.LastEntry().Message)

}
