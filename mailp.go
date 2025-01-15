package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/commands"
	"github.com/emersion/go-imap/responses"
	"github.com/emersion/go-sasl"
)

type MailpConf struct{}

type Mailp struct {
	conf MailpConf
	d    *net.Dialer

	l   net.Listener
	cid int64
}

func mailp() error {
	return (&Mailp{
		conf: MailpConf{},
	}).Start()
}

func (m *Mailp) init() error {
	m.d = &net.Dialer{Timeout: 2 * time.Second}

	return nil
}

func (m *Mailp) Start() error {
	if err := m.init(); err != nil {
		return err
	}

	l, err := net.Listen("tcp", ":1234")
	if err != nil {
		return err
	}
	m.l = l

	fmt.Printf("listing on %s\n", l.Addr().String())

	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}

		go m.serve(c)
	}
}

func (m *Mailp) Stop() error {
	return m.l.Close()
}

var log2 = log.New(os.Stderr, "+ ", 0)

func (m *Mailp) serve(c net.Conn) error {
	cid := atomic.AddInt64(&m.cid, 1)
	log2.Printf("conn(%d) %s\n", cid, c.RemoteAddr())

	defer func() {
		log2.Printf("conn(%d) close\n", cid)
		c.Close()
	}()

	// FIXME: turn off prefix write before pipe
	// FIXME: only turn on prefix write for debug, contains lots of creds

	c_r := imap.NewReader(bufio.NewReader(io.TeeReader(c, newPrefixWriter("c> ", os.Stderr))))
	c_w := imap.NewWriter(bufio.NewWriter(io.MultiWriter(c, newPrefixWriter("c< ", os.Stderr))))

	caps := []string{"CAPABILITY", "IMAP4rev1", "AUTH=PLAIN", "LITERAL+", "SASL-IR"}
	args := []any{}
	for _, cap := range caps {
		args = append(args, cap)
	}
	greeting := &imap.StatusResp{
		Type:      imap.StatusRespOk,
		Code:      imap.CodeCapability,
		Arguments: args,
		Info:      "IMAP4rev1 Service Ready",
	}
	if err := greeting.WriteTo(c_w); err != nil {
		return err
	}

	n := 0

handshake:
	for {
		n += 1

		if n >= 10 {
			// 一般不需要这么多
			return nil
		}

		fields, err := c_r.ReadLine()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			if imap.IsParseError(err) {
				(&imap.StatusResp{
					Type: imap.StatusRespBad,
					Info: err.Error(),
				}).WriteTo(c_w)
				// TODO: return ??

				continue handshake
			}
			return err
		}

		cmd := &imap.Command{}
		if err := cmd.Parse(fields); err != nil {
			(&imap.StatusResp{
				Tag:  cmd.Tag,
				Type: imap.StatusRespBad,
				Info: err.Error(),
			}).WriteTo(c_w)
			// TODO: return ??

			continue handshake
		}

		switch cmd.Name {
		case "CAPABILITY":
			(&responses.Capability{Caps: caps}).WriteTo(c_w)
			// TODO: fill info
			(&imap.StatusResp{
				Tag:  cmd.Tag,
				Type: imap.StatusRespOk,
			}).WriteTo(c_w)

			continue handshake

		case "AUTHENTICATE":
			authCmd := &commands.Authenticate{}
			authCmd.Parse(cmd.Arguments)
			var cc commands.AuthenticateConn = &authConn{c_r, c_w}
			mechanisms := map[string]sasl.Server{
				sasl.Plain: sasl.NewPlainServer(func(identity, username, password string) error {
					if identity != "" && identity != username {
						return errors.New("Identities not supported")
					}

					if username == "abc" && password == "123" {
						// set username for connect upstream
						return nil
					}

					return fmt.Errorf("bad username or password")
				}),
			}
			err := authCmd.Handle(mechanisms, cc)
			if err != nil {
				(&imap.StatusResp{
					Tag:  cmd.Tag,
					Type: imap.StatusRespNo,
					Info: err.Error(),
				}).WriteTo(c_w)

				// 鉴权失败，可以给Client多几次机会
				continue handshake
			}

			// 鉴权成功，接下来开始跟 upstream 对接
			(&imap.StatusResp{
				Tag:  cmd.Tag,
				Type: imap.StatusRespOk,
			}).WriteTo(c_w)

			break handshake

		default:
			log2.Printf("todo cmd %s(%s)", cmd.Tag, cmd.Name)
		}

	}

	// connect upstream
	err := func() error {
		addr := "127.0.0.1:1233"

		log2.Printf("conn(%d) connect upstream: %s", cid, addr)

		c2, err := m.d.Dial("tcp", addr)
		if err != nil {
			return err
		}
		c3 := c2
		defer c3.Close()

		log2.Printf("conn(%d) connect upstream: %s (ok)", cid, addr)

		// TODO: imap.Client Execute() like

		c3_r := imap.NewReader(bufio.NewReader(io.TeeReader(c3, newPrefixWriter("s> ", os.Stderr))))
		c3_w := imap.NewWriter(bufio.NewWriter(io.MultiWriter(c3, newPrefixWriter("s< ", os.Stderr))))

		{
			ret, err := imap.ReadResp(c3_r)
			if err != nil {
				return err
			}

			// log2.Printf("conn(%d) server got %+v\n", cid, ret)

			vv, ok := ret.(*imap.StatusResp)
			if !ok {
				// log
				return fmt.Errorf("want greet")
			}
			if !(vv.Tag == "*" && vv.Type == imap.StatusRespOk) {
				return fmt.Errorf("bad greet")
			}

		}

		// AUTH
		username := "username"
		password := "password"
		mech, ir, err := sasl.NewPlainClient(username, username, password).Start()
		if err != nil {
			return err
		}

		log2.Printf("conn(%d) login upstream as %s", cid, username)

		cmdr := &commands.Authenticate{
			Mechanism:       mech,
			InitialResponse: ir,
		}
		cmd := cmdr.Command()
		cmd.Tag = "a.1"

		if err := cmd.WriteTo(c3_w); err != nil {
			return err
		}

		for {
			ret, err := imap.ReadResp(c3_r)
			if err != nil {
				return err
			}
			log2.Printf("conn(%d) server auth ret: %+v\n", cid, ret)

			if vv, ok := ret.(*imap.DataResp); ok {
				name, fields, ok := imap.ParseNamedResp(vv)
				if !ok || name != "CAPABILITY" {
					return fmt.Errorf("auth bad data")
				}
				// TODO: use fields
				_ = fields
				continue
			}

			vv, ok := ret.(*imap.StatusResp)
			if !ok {
				return fmt.Errorf("auth bad")
			}
			if !(vv.Tag == cmd.Tag && vv.Type == imap.StatusRespOk) {
				return fmt.Errorf("auth fail")
			}

			break
		}

		log2.Printf("conn(%d) pipe\n", cid)

		// PIPE
		pipe(c_r, c_w, c3_r, c3_w)

		return nil
	}()

	if err != nil {
		(&imap.StatusResp{
			Type: imap.StatusRespBye,
			Info: err.Error(),
		}).WriteTo(c_w)

		return err
	}

	return nil
}

type authConn struct {
	io.Reader
	w *imap.Writer
}

func (cc *authConn) WriteResp(res imap.WriterTo) error {
	return res.WriteTo(cc.w)
}

type prefixWriter struct {
	w  io.Writer
	ch []byte
}

func newPrefixWriter(ch string, w io.Writer) io.Writer {
	return &prefixWriter{
		w:  w,
		ch: []byte(ch),
	}
}
func (w *prefixWriter) Write(p []byte) (n int, err error) {
	w.w.Write(w.ch)
	return w.w.Write(p)
}
