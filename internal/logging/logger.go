package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	CurrentLevel = LevelInfo
	AuditEnabled = false
	AuditFile    string
)

const (
	ColorReset = "\033[0m"
	ColorInfo  = "\033[32m"
	ColorWarn  = "\033[33m"
	ColorError = "\033[31m"
	ColorDebug = "\033[36m"
)

func InitAuditLog() error {
	if !AuditEnabled {
		return nil
	}
	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		stateHome = filepath.Join(home, ".local", "state")
	}
	auditDir := filepath.Join(stateHome, "cloakid")
	if err := os.MkdirAll(auditDir, 0700); err != nil {
		return err
	}
	AuditFile = filepath.Join(auditDir, "audit.log")
	// Touch and chmod 600
	f, err := os.OpenFile(AuditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	return f.Close()
}

func AuditLog(msg string) {
	if !AuditEnabled || AuditFile == "" {
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	f, err := os.OpenFile(AuditFile, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] [%s] %s\n", timestamp, os.Getenv("USER"), msg)
}

func logWithColor(level LogLevel, color, prefix, msg string) {
	if CurrentLevel > level {
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	useColor := true
	if fi, _ := os.Stdout.Stat(); (fi.Mode() & os.ModeCharDevice) == 0 {
		useColor = false
	}
	if useColor {
		fmt.Printf("%s[%s] %s%s%s\n", color, timestamp, prefix, msg, ColorReset)
	} else {
		fmt.Printf("[%s] %s%s\n", timestamp, prefix, msg)
	}
}

func Info(format string, args ...interface{}) {
	logWithColor(LevelInfo, ColorInfo, "", fmt.Sprintf(format, args...))
}

func Warn(format string, args ...interface{}) {
	logWithColor(LevelWarn, ColorWarn, "WARN: ", fmt.Sprintf(format, args...))
}

func Error(format string, args ...interface{}) {
	logWithColor(LevelError, ColorError, "ERROR: ", fmt.Sprintf(format, args...))
}

func Fatal(format string, args ...interface{}) {
	Error(format, args...)
	os.Exit(1)
}

func Debug(format string, args ...interface{}) {
	logWithColor(LevelDebug, ColorDebug, "DEBUG: ", fmt.Sprintf(format, args...))
}
