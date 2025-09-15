package errors

import (
	"fmt"
)

type ProtocolError struct {
	Message string
	Cause   error
}

func (e *ProtocolError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *ProtocolError) Unwrap() error {
	return e.Cause
}

// IsProtocolError checks if an error is a protocol error
func IsProtocolError(err error) bool {
	if _, ok := err.(*ProtocolError); ok {
		return true
	}
	return false
}

// WrapProtocolError wraps an existing error as a protocol error
func WrapProtocolError(err error, message string) *ProtocolError {
	return &ProtocolError{
		Message: message,
		Cause:   err,
	}
}

// ProtocolErrorf creates a new protocol error with formatted message
func ProtocolErrorf(format string, args ...interface{}) *ProtocolError {
	return &ProtocolError{
		Message: fmt.Sprintf(format, args...),
		Cause:   nil,
	}
}
