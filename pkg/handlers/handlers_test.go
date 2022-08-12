package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/microlib/simple"
	"lmzsoftware.com/lzuccarelli/golang-blockchain-insert/pkg/connectors"
)

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("Injected error")
}

// Fake all connections
type FakeConnections struct {
	Http *http.Client
	L    *simple.Logger
	Flag string
}

func (r *FakeConnections) Do(req *http.Request) (*http.Response, error) {
	return r.Http.Do(req)
}

func (r *FakeConnections) Error(msg string, val ...interface{}) {
	r.L.Error(fmt.Sprintf(msg, val...))
}

func (r *FakeConnections) Info(msg string, val ...interface{}) {
	r.L.Info(fmt.Sprintf(msg, val...))
}

func (r *FakeConnections) Debug(msg string, val ...interface{}) {
	r.L.Debug(fmt.Sprintf(msg, val...))
}

func (r *FakeConnections) Trace(msg string, val ...interface{}) {
	r.L.Trace(fmt.Sprintf(msg, val...))
}

func (r *FakeConnections) Close() {
}

func (r *FakeConnections) Force() {
	r.Flag = "error"
}

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

//NewHttpTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewHttpTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

// NewTestConnections - create all mock connections
func NewTestConnections(file string, code int, logger *simple.Logger) connectors.Clients {

	// we first load the json payload to simulate a call to middleware
	// for now just ignore failures.
	data, err := ioutil.ReadFile(file)
	if err != nil {
		logger.Error(fmt.Sprintf("file data %v\n", err))
		panic(err)
	}
	httpclient := NewHttpTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: code,
			// Send response to be tested

			Body: ioutil.NopCloser(bytes.NewBufferString(string(data))),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})

	conns := &FakeConnections{Http: httpclient, L: logger}
	return conns
}

func TestHandlers(t *testing.T) {

	logger := &simple.Logger{Level: "info"}

	t.Run("IsAlive : should pass", func(t *testing.T) {
		var STATUS int = 200
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v2/sys/info/isalive", nil)
		NewTestConnections("../../tests/payload.json", STATUS, logger)
		handler := http.HandlerFunc(IsAlive)
		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "IsAlive", rr.Code, STATUS))
		}
	})

	t.Run("EncryptInsertToBlockchain : POST should pass", func(t *testing.T) {
		var STATUS int = 200
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		data, _ := ioutil.ReadFile("../../tests/input-to-encrypt.json")
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/blockchain", bytes.NewBuffer([]byte(data)))
		conn := NewTestConnections("../../tests/payload.json", STATUS, logger)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			EncryptInsertToBlockChain(w, r, conn)
		})
		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "EncryptInsertToBlockchain", rr.Code, STATUS))
		}
	})

	t.Run("EncryptInsertToBlockchain : POST should fail (force readall error)", func(t *testing.T) {
		var STATUS int = 500
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/blockchain", errReader(0))
		conn := NewTestConnections("../../tests/payload.json", STATUS, logger)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			EncryptInsertToBlockChain(w, r, conn)
		})
		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "EncryptInsertToBlockchain", rr.Code, STATUS))
		}
	})

	t.Run("EncryptInsertToBlockchain : POST should fail (json data)", func(t *testing.T) {
		var STATUS int = 500
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/blockchain", bytes.NewBuffer([]byte("")))
		conn := NewTestConnections("../../tests/payload.json", STATUS, logger)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			EncryptInsertToBlockChain(w, r, conn)
		})
		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "EncryptInsertToBlockchain", rr.Code, STATUS))
		}
	})

	t.Run("EncryptInsertToBlockchain : POST should fail (forced Do error)", func(t *testing.T) {
		var STATUS int = 500
		data, _ := ioutil.ReadFile("../../tests/input-to-encrypt.json")
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/blockchain", bytes.NewBuffer(data))
		conn := NewTestConnections("../../tests/payload.json", STATUS, logger)
		conn.Force()
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			EncryptInsertToBlockChain(w, r, conn)
		})
		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "EncryptInsertToBlockchain", rr.Code, STATUS))
		}
	})

}
