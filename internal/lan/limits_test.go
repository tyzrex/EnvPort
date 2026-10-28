package lan

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestConnectionLimitReleasesAndShutdownUnblocksAccept(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := &boundedListener{Listener: base, slots: make(chan struct{}, 1), done: make(chan struct{})}
	defer limited.Close()
	firstPeer, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer firstPeer.Close()
	first, err := limited.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	secondPeer, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer secondPeer.Close()
	accepted := make(chan net.Conn, 1)
	failures := make(chan error, 1)
	go func() {
		c, e := limited.Accept()
		if e != nil {
			failures <- e
			return
		}
		accepted <- c
	}()
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("connection limit was bypassed")
	case <-time.After(50 * time.Millisecond):
	}
	first.Close()
	var second net.Conn
	select {
	case second = <-accepted:
		defer second.Close()
	case e := <-failures:
		t.Fatal(e)
	case <-time.After(3 * time.Second):
		t.Fatal("closing a connection did not release its slot")
	}
	go func() { _, e := limited.Accept(); failures <- e }()
	limited.Close()
	select {
	case e := <-failures:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatal("shutdown returned unexpected accept error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown left accept blocked by connection limit")
	}
}
