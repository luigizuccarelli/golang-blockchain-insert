package connectors

import (
	"net/http"
)

// Client Interface - allows for different implmentations for testing and real environments
type Clients interface {
	Error(string, ...interface{})
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Trace(string, ...interface{})
	Do(req *http.Request) (*http.Response, error)
	Close()
	Force()
}
