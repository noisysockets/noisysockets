// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally:
 *
 * Copyright (c) 2016 Daniel Garcia
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// Package multilistener provides a net.Listener that multiplexes connections from
// multiple listeners.
package multilistener

import (
	"errors"
	"net"
	"sync"
)

var _ net.Listener = &multiListener{}

// multiListener implements a net.multiListener interface but multiplexes connections
// from multiple listeners.
type multiListener struct {
	listeners []net.Listener
	closeOnce sync.Once
	closing   chan struct{}
	conns     chan acceptResults
}

type acceptResults struct {
	conn net.Conn
	err  error
}

// New creates an instance of a Listener using the given listeners. You must
// pass at least one listener. The new listener object listens for new connection
// on all the given listeners.
func New(listeners ...net.Listener) (*multiListener, error) {
	if len(listeners) == 0 {
		return nil, errors.New("multilistener requires at least 1 listener")
	}

	lis := &multiListener{
		listeners: listeners,
		closing:   make(chan struct{}),
		conns:     make(chan acceptResults),
	}

	for _, listener := range lis.listeners {
		go lis.acceptLoop(listener)
	}

	return lis, nil
}

// Addr returns the address of the first listener the multi-listener is using.
// The address of other listeners are not available.
func (ml *multiListener) Addr() net.Addr {
	return ml.listeners[0].Addr()
}

// Close will close the multi-listener by iterating over its listeners and calling
// Close() on each one. If an error is encountered, it is returned. If multiple
// errors are encountered they are returned in a MutiError. Close will also shut down
// the background goroutines that are calling Accept() on the underlying listeners.
//
// Calling Close() more than once will cause it to panic.
func (ml *multiListener) Close() error {
	var errs []error
	ml.closeOnce.Do(func() {
		close(ml.closing)
		for i := range ml.listeners {
			err := ml.listeners[i].Close()
			if err != nil {
				errs = append(errs, err)
			}
		}
	})
	return errors.Join(errs...)
}

// Accept will wait for a result from calling Accept from the underlying listeners.
// It will return an error if the multi-listener is closed.
func (ml *multiListener) Accept() (net.Conn, error) {
	select {
	case acceptResult, ok := <-ml.conns:
		if ok {
			return acceptResult.conn, acceptResult.err
		}
		return nil, errors.New("closed conn channel")
	case <-ml.closing:
		return nil, errors.New("listener is closed")
	}
}

// acceptLoop continually accepts connections from the given listener. It forwards the result
// of the .Accept() method to a channel on the listener. When a user of the Listener object
// calls Accept(), it receives a value from that channel. Closing the listener will cause
// this acceptLoop to exit.
func (ml *multiListener) acceptLoop(lis net.Listener) {
	for {
		conn, err := lis.Accept()
		r := acceptResults{
			conn: conn,
			err:  err,
		}
		select {
		case ml.conns <- r:
		case <-ml.closing:
			if r.err == nil {
				r.conn.Close()
			}
			return
		}
	}
}
