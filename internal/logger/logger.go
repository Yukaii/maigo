package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/charmbracelet/log"
)

// Logger wraps slog.Logger for structured logging
type Logger struct {
	*slog.Logger
}

// Config holds logger configuration
type Config struct {
	Level  string // debug, info, warn, error
	Format string // json, text
}

// NewLogger creates a new logger instance
func NewLogger(config Config) *Logger {
	var level slog.Level
	switch strings.ToLower(config.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
		AddSource: true,
	}

	switch strings.ToLower(config.Format) {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		// Use charmbracelet/log for pretty terminal output in development
		charmLogger := log.NewWithOptions(os.Stdout, log.Options{
			ReportCaller:    true,
			ReportTimestamp: true,
			TimeFormat:      "15:04:05",
		})
		charmLogger.SetLevel(logLevelToCharm(level))
		
		// Create a wrapper that implements slog.Handler interface
		handler = &charmHandler{logger: charmLogger}
	}

	logger := slog.New(handler)
	return &Logger{Logger: logger}
}

// logLevelToCharm converts slog.Level to charmbracelet log level
func logLevelToCharm(level slog.Level) log.Level {
	switch level {
	case slog.LevelDebug:
		return log.DebugLevel
	case slog.LevelInfo:
		return log.InfoLevel
	case slog.LevelWarn:
		return log.WarnLevel
	case slog.LevelError:
		return log.ErrorLevel
	default:
		return log.InfoLevel
	}
}

// charmHandler wraps charmbracelet/log to implement slog.Handler
type charmHandler struct {
	logger *log.Logger
}

func (h *charmHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.logger.GetLevel() <= logLevelToCharm(level)
}

func (h *charmHandler) Handle(ctx context.Context, record slog.Record) error {
	level := logLevelToCharm(record.Level)
	
	// Build key-value pairs
	var keyvals []interface{}
	record.Attrs(func(attr slog.Attr) bool {
		keyvals = append(keyvals, attr.Key, attr.Value.Any())
		return true
	})

	switch level {
	case log.DebugLevel:
		h.logger.Debug(record.Message, keyvals...)
	case log.InfoLevel:
		h.logger.Info(record.Message, keyvals...)
	case log.WarnLevel:
		h.logger.Warn(record.Message, keyvals...)
	case log.ErrorLevel:
		h.logger.Error(record.Message, keyvals...)
	default:
		h.logger.Info(record.Message, keyvals...)
	}

	return nil
}

func (h *charmHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// For simplicity, return the same handler
	// In a more sophisticated implementation, you'd create a new handler with the attrs
	return h
}

func (h *charmHandler) WithGroup(name string) slog.Handler {
	// For simplicity, return the same handler
	// In a more sophisticated implementation, you'd create a new handler with the group
	return h
}

// Global logger instance
var globalLogger *Logger

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger *Logger) {
	globalLogger = logger
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		// Create a default logger if none is set
		globalLogger = NewLogger(Config{
			Level:  "info",
			Format: "text",
		})
	}
	return globalLogger
}

// Convenience functions that use the global logger
func Debug(msg string, args ...any) {
	GetGlobalLogger().Debug(msg, args...)
}

func Info(msg string, args ...any) {
	GetGlobalLogger().Info(msg, args...)
}

func Warn(msg string, args ...any) {
	GetGlobalLogger().Warn(msg, args...)
}

func Error(msg string, args ...any) {
	GetGlobalLogger().Error(msg, args...)
}

// With creates a new logger with the given attributes
func With(args ...any) *Logger {
	return &Logger{Logger: GetGlobalLogger().With(args...)}
}

// WithGroup creates a new logger with the given group name
func WithGroup(name string) *Logger {
	return &Logger{Logger: GetGlobalLogger().WithGroup(name)}
}
