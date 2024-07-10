// rhttp2 provides a set of simple APIs for creating HTTP/2 servers and clients
// that use roast for auth. It is meant to simplify the process of using roast
// to protect connections. It is explicitly an http2 focused library because
// there are many cases in HTTP 1.x where the client and server will hang up
// connections. This is undesirable for a transport like roast where each
// connection has both a roast handshake and TLS handshake involved in setting
// them up. Reusing the underlying connection is a pretty notable improvement.
package rhttp2
