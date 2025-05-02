package testutils

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http/httptrace"
	"testing"
	"time"
)

// WithHTTPTrace returns a new context with HTTP trace hooks that log to the test logger
func WithHTTPTrace(t *testing.T, ctx context.Context) context.Context {
	t.Helper()

	tid := func() string {
		id := make([]byte, 4)
		rand.Read(id)
		return hex.EncodeToString(id)
	}

	ctid := tid()

	var (
		start    time.Time = time.Now()
		previous time.Time = start
	)
	logger := func(format string, args ...interface{}) {
		t.Helper()

		now := time.Now()
		delta := now.Sub(previous)
		previous = now

		t.Logf("%s [%v][%v]: %s", ctid, now.Sub(start).Milliseconds(), delta, fmt.Sprintf(format, args...))
	}

	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			logger("GetConn: %s", hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			logger("GotConn: %+v", info)
		},
		PutIdleConn: func(err error) {
			logger("PutIdleConn: %v", err)
		},
		GotFirstResponseByte: func() {
			logger("GotFirstResponseByte")
		},
		Got100Continue: func() {
			logger("Got100Continue")
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			logger("DNSStart: %+v", info)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			logger("DNSDone: %+v", info)
		},
		ConnectStart: func(network, addr string) {
			logger("ConnectStart: %s %s", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			logger("ConnectDone: %s %s %v", network, addr, err)
		},
		TLSHandshakeStart: func() {
			logger("TLSHandshakeStart")
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			logger("TLSHandshakeDone: %v", err)
		},
		WroteHeaderField: func(key string, value []string) {
			logger("WroteHeaderField: %s: %v", key, value)
		},
		WroteHeaders: func() {
			logger("WroteHeaders")
		},
		Wait100Continue: func() {
			logger("Wait100Continue")
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			logger("WroteRequest: %+v", info)
		},
	}

	return httptrace.WithClientTrace(ctx, trace)
}
