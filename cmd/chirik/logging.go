package main

import (
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/reconquest/karma-go"

	charmlog "github.com/charmbracelet/log"
)

const loggerPrefix = "chirik"

type logIndentWriter struct {
	writer io.Writer
	indent string
}

func loggerNew(writer io.Writer) *log.Logger {
	level := charmlog.InfoLevel
	if os.Getenv("CHIRIK_DEBUG") != "" {
		level = charmlog.DebugLevel
	}

	logger := charmlog.NewWithOptions(writer, charmlog.Options{
		Prefix:          loggerPrefix,
		ReportTimestamp: true,
		TimeFormat:      time.TimeOnly,
		Level:           level,
	})

	header := time.TimeOnly + " ERRO " + loggerPrefix + ": "

	return log.New(&logIndentWriter{
		writer: logger.StandardLog().Writer(),
		indent: strings.Repeat(" ", len(header)),
	}, "", 0)
}

func (writer *logIndentWriter) Write(data []byte) (int, error) {
	message := strings.TrimSuffix(string(data), "\n")

	message = strings.ReplaceAll(message, "\n", "\n"+writer.indent)

	_, err := io.WriteString(writer.writer, message+"\n")
	if err != nil {
		return 0, karma.Format(err, "write log message")
	}

	return len(data), nil
}
