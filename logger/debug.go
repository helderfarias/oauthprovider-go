// +build debug

package logger

import "log"

func Debug(fmt string, args ...interface{}) {
	log.Printf("[oauthprovider-debug] "+fmt, args...)
}

func Info(fmt string, args ...interface{}) {
	log.Printf("[oauthprovider-info] "+fmt, args...)
}

func Error(fmt string, args ...interface{}) {
	log.Printf("[oauthprovider-error] "+fmt, args...)
}
