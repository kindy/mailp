package main

import (
	"io"
)

func pipeChanFromConn(conn io.Reader) chan []byte {
	c := make(chan []byte)

	go func() {
		b := make([]byte, 512)

		for {
			n, err := conn.Read(b)
			if n > 0 {
				res := make([]byte, n)
				// Copy the buffer so it doesn't get changed while read by the recipient.
				copy(res, b[:n])
				c <- res
			}
			if err != nil {
				c <- nil
				break
			}
		}
	}()

	return c
}

type pipeFlusher interface {
	Flush() error
}

func pipe(c1_r io.Reader, c1_w io.Writer, c2_r io.Reader, c2_w io.Writer) {
	chan1 := pipeChanFromConn(c1_r)
	chan2 := pipeChanFromConn(c2_r)

	for {
		select {
		case b1 := <-chan1:
			if b1 == nil {
				return
			} else {
				c2_w.Write(b1)
				if wf, ok := c2_w.(pipeFlusher); ok {
					wf.Flush()
				}
			}
		case b2 := <-chan2:
			if b2 == nil {
				return
			} else {
				c1_w.Write(b2)
				if wf, ok := c1_w.(pipeFlusher); ok {
					wf.Flush()
				}
			}
		}
	}
}
