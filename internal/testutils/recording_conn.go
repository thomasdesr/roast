package testutils

import "net"

type RecordingConn struct {
	net.Conn

	DataSent []byte
	DataRecv []byte
}

func (c *RecordingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	c.DataRecv = append(c.DataRecv, b[:n]...)
	return
}

func (c *RecordingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	c.DataSent = append(c.DataSent, b[:n]...)
	return
}
