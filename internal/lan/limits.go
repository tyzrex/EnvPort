package lan

import (
	"net"
	"sync"
)

// Bound open TCP/TLS connections as well as authenticated object operations.
// A slow unauthenticated handshake must not allocate unbounded server resources.
type boundedListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func (l *boundedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &boundedConnection{Conn: c, release: func() { <-l.slots }}, nil
}
func (l *boundedListener) Close() error {
	var err error
	l.once.Do(func() { close(l.done); err = l.Listener.Close() })
	return err
}

type boundedConnection struct {
	net.Conn
	release func()
	once    sync.Once
	err     error
}

func (c *boundedConnection) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.release() })
	return c.err
}
