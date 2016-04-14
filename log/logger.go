package log

import (
	"fmt"
	"time"
)

const (
	DEBUG int32 = iota
	INFO
	WARN
	ERROR
)

var levelFlags = map[int32]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
}

type Log interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Error(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Disable()
	SetLevel(level int32)
}

type DefaultLogger struct {
	disabled bool
	level    int32
}

var Logger Log = new(DefaultLogger)

func (l *DefaultLogger) log(level string, format string, args ...interface{}) {
	fmt.Printf("[%s] %s - ", level, time.Now().In(time.UTC).Format("2006-01-02T15:04:05Z07:00"))
	fmt.Println(fmt.Sprintf(format, args...))
}

func GetLevelFlagName(level int32) string {
	return levelFlags[level]
}

func (l *DefaultLogger) Debug(format string, args ...interface{}) {
	if !l.disabled && l.level == DEBUG {
		l.log("DEBUG", format, args...)
	}
}

func (l *DefaultLogger) Info(format string, args ...interface{}) {
	if !l.disabled && (l.level >= INFO || l.level == DEBUG) {
		l.log("INFO", format, args...)
	}
}

func (l *DefaultLogger) Warn(format string, args ...interface{}) {
	if !l.disabled && (l.level >= WARN || l.level == DEBUG) {
		l.log("WARN", format, args...)
	}
}

func (l *DefaultLogger) Error(format string, args ...interface{}) {
	if !l.disabled && (l.level >= ERROR || l.level == DEBUG) {
		l.log("ERROR", format, args...)
	}
}

func (l *DefaultLogger) Disable() {
	l.disabled = true
}

func (l *DefaultLogger) SetLevel(level int32) {
	l.level = level
}
