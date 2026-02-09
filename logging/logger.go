package logging

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger provides thread-safe logging functionality
type Logger struct {
	level    LogLevel
	logFile  *os.File
	mu       sync.Mutex
	fileName string
}

// NewLogger creates a new logger with default settings
func NewLogger() *Logger {
	return &Logger{
		level: INFO, // Default log level
	}
}

// SetLevel sets the log level from a string
func (l *Logger) SetLevel(levelStr string) {
	level, ok := LogLevelFromString(levelStr)
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid log level: %s, using INFO\n", levelStr)
		l.level = INFO
		return
	}
	l.level = level
}

// SetOutputFile sets the output file for logs
func (l *Logger) SetOutputFile(fileName string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Close existing file if open
	if l.logFile != nil {
		l.logFile.Close()
		l.logFile = nil
	}

	// Open new log file
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.logFile = file
	l.fileName = fileName
	return nil
}

// log writes a message to the log with the specified level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return // Skip logging if level is below current threshold
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Format the log message
	// Optimize: Use single fmt.Sprintf with pre-allocated slice to avoid allocation in hot path
	now := time.Now().Format("2006-01-02 15:04:05")
	levelName := level.String()

	// Pre-allocate slice with known capacity to avoid allocation on every log call
	allArgs := make([]interface{}, 0, len(args)+2)
	allArgs = append(allArgs, now, levelName)
	allArgs = append(allArgs, args...)
	logLine := fmt.Sprintf("[%s] %s "+format+"\n", allArgs...)

	// Write to console
	fmt.Print(logLine)

	// Write to file if configured
	if l.logFile != nil {
		_, _ = l.logFile.WriteString(logLine)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}
