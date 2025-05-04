// Package rhttp2 provides a set of simple APIs for creating HTTP/2 servers and
// clients that use roast for authentication and authorization. It is designed
// to simplify the process of using roast to protect connections in HTTP/2
// environments.
//
// The package is explicitly HTTP/2 focused because HTTP/1.x clients and servers
// often close connections, which is inefficient for roast-protected connections
// that require both a roast handshake and TLS handshake for setup. Connection
// reuse in HTTP/2 provides significant performance improvements in these
// scenarios.
//
// Additionally there is also a reverse proxy implementation that can be used
// to forward requests to a target URL and passing through peer metadata
// information as an HTTP header.
package rhttp2
