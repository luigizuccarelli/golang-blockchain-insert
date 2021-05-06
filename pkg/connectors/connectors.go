package connectors

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/microlib/simple"
)

// Connections struct - all backend connections in a common object
type Connections struct {
	Http *http.Client
	L    *simple.Logger
}

func (r *Connections) Do(req *http.Request) (*http.Response, error) {
	return r.Http.Do(req)
}

func (r *Connections) Error(msg string, val ...interface{}) {
	r.L.Error(fmt.Sprintf(msg, val...))
}

func (r *Connections) Info(msg string, val ...interface{}) {
	r.L.Info(fmt.Sprintf(msg, val...))
}

func (r *Connections) Debug(msg string, val ...interface{}) {
	r.L.Debug(fmt.Sprintf(msg, val...))
}

func (r *Connections) Trace(msg string, val ...interface{}) {
	r.L.Trace(fmt.Sprintf(msg, val...))
}

func (r *Connections) Close() {
	// intentionally left empty
}

func (r *Connections) Force() {
	// intentionally left empty
}

// NewClientConnectors returns Connectors struct
func NewClientConnections(logger *simple.Logger) Clients {
	// set up http object
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: tr}

	conns := &Connections{Http: httpClient, L: logger}
	logger.Debug(fmt.Sprintf("Connection details %v\n", conns))
	return conns
}
