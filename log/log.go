/*
Copyright 2016 The Thor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package log

import (
	"github.com/astaxie/beego/logs"
)

// Log levels to control the logging output.
const (
	LevelEmergency = iota
	LevelAlert
	LevelCritical
	LevelError
	LevelWarning
	LevelNotice
	LevelInformational
	LevelDebug
)

// ThorLog references the used application logger.
var (
	ThorLog = logs.NewLogger(100)

	LevelMap = map[string]int{
		"Emergency": LevelEmergency,
		"Alert":  LevelAlert,
		"Critical": LevelCritical,
		"Error": LevelError,
		"Warning": LevelWarning,
		"Notice": LevelNotice,
		"Informational": LevelInformational,
		"Info": LevelInformational,
		"Debug": LevelDebug,

	}
)

// SetLevel sets the global log level used by the simple logger.
func SetLevel(l int) {
	ThorLog.SetLevel(l)
}

// SetLogFuncCall set the CallDepth, default is 3
func SetLogFuncCall(b bool) {
	ThorLog.EnableFuncCallDepth(b)
	ThorLog.SetLogFuncCallDepth(3)
}

// SetLogger sets a new logger.
func SetLogger(adaptername string, config string) error {
	err := ThorLog.SetLogger(adaptername, config)
	if err != nil {
		return err
	}
	return nil
}

// Emergency
func Emergency(format string, v ...interface{}) {
	ThorLog.Emergency(format, v...)
}

// Alert
func Alert(format string, v ...interface{}) {
	ThorLog.Alert(format, v...)
}

// Critical
func Critical(format string, v ...interface{}) {
	ThorLog.Critical(format, v...)
}

// Error
func Error(format string, v ...interface{}) {
	ThorLog.Error(format, v...)
}

// Warning
func Warning(format string, v ...interface{}) {
	ThorLog.Warning(format, v...)
}

// Warn
func Warn(format string, v ...interface{}) {
	ThorLog.Warn(format, v...)
}

// Notice
func Notice(format string, v ...interface{}) {
	ThorLog.Notice(format, v...)
}

// Informational
func Informational(format string, v ...interface{}) {
	ThorLog.Informational(format, v...)
}

// Info (compatibility alias for Informational)
func Info(format string, v ...interface{}) {
	ThorLog.Info(format, v...)
}

// Debug
func Debug(format string, v ...interface{}) {
	ThorLog.Debug(format, v...)
}

// Trace (compatibility alias for Debug)
func Trace(format string, v ...interface{}) {
	ThorLog.Trace(format, v...)
}
