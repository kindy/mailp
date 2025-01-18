package main

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
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

type Mailp struct {
	conf *MailpConf
	d    *net.Dialer

	l   net.Listener
	cid int64
	log *log.Logger
}

func mailp(conf *MailpConf) error {
	mp := &Mailp{conf: conf}

	return mp.Start()
}

func (mp *Mailp) init() error {
	mp.d = &net.Dialer{Timeout: 2 * time.Second}
	mp.log = log.New(os.Stderr, "+ ", 0)

	return nil
}

func (mp *Mailp) Start() error {
	if err := mp.init(); err != nil {
		return err
	}

	var l net.Listener
	{
		var err error

		if mp.conf.Imap.Tls.Enabled {
			var cert tls.Certificate
			cert, err = tls.LoadX509KeyPair(mp.conf.Imap.Tls.Cert, mp.conf.Imap.Tls.Key)
			if err == nil {
				l, err = tls.Listen("tcp", mp.conf.Imap.Addr, &tls.Config{
					Certificates: []tls.Certificate{cert},
				})
			}
		} else {
			l, err = net.Listen("tcp", mp.conf.Imap.Addr)
		}
		if err != nil {
			return err
		}
	}

	mp.l = l

	fmt.Printf("listing on %s\n", l.Addr().String())

	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}

		go mp.serve(c)
	}
}

func (mp *Mailp) Stop() error {
	// TODO: wait all conns done, or close them?
	return mp.l.Close()
}

func (mp *Mailp) serve(c net.Conn) error {
	cid := atomic.AddInt64(&mp.cid, 1)
	mp.log.Printf("conn(%d) %s\n", cid, c.RemoteAddr())

	defer func() {
		mp.log.Printf("conn(%d) close\n", cid)
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

	var connUsername string

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
						return errors.New("identities not supported")
					}

					if user, ok := mp.conf.Imap.Users[username]; ok {
						if subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) == 1 {
							connUsername = username
							// set username for connect upstream
							return nil
						}
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
			mp.log.Printf("todo cmd %s(%s)", cmd.Tag, cmd.Name)
		}

	}

	// connect upstream
	err := func() error {
		// mp.log.Printf("user %s", connUsername)
		connUpConf := mp.conf.Imap.Users[connUsername].Upstream

		addr := connUpConf.Addr

		mp.log.Printf("conn(%d) connect upstream: %s", cid, addr)

		c2, err := mp.d.Dial("tcp", addr)
		if err != nil {
			return err
		}
		// TODO: tls (c3 is for tls)
		c3 := c2
		defer c3.Close()

		mp.log.Printf("conn(%d) connect upstream: %s (ok)", cid, addr)

		c3_r := imap.NewReader(bufio.NewReader(io.TeeReader(c3, newPrefixWriter("s> ", os.Stderr))))
		c3_w := imap.NewWriter(bufio.NewWriter(io.MultiWriter(c3, newPrefixWriter("s< ", os.Stderr))))

		{
			ret, err := imap.ReadResp(c3_r)
			if err != nil {
				return err
			}

			// m.log.Printf("conn(%d) server got %+v\n", cid, ret)

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
		if connUpConf.Auth.Type != "plain" {
			return fmt.Errorf("upstream auth support plain, got %s", connUpConf.Auth.Type)
		}

		username := connUpConf.Auth.Username
		password := connUpConf.Auth.Password
		mp.log.Printf("conn(%d) login upstream as %s", cid, username)

		mech, ir, err := sasl.NewPlainClient(username, username, password).Start()
		if err != nil {
			return err
		}
		cmdr := &commands.Authenticate{
			Mechanism:       mech,
			InitialResponse: ir,
		}
		cmd := cmdr.Command()
		cmd.Tag = "mailp.1"

		// TODO: we need imap.Client.Execute()
		if err := cmd.WriteTo(c3_w); err != nil {
			return err
		}
		for {
			ret, err := imap.ReadResp(c3_r)
			if err != nil {
				return err
			}
			mp.log.Printf("conn(%d) server auth ret: %+v\n", cid, ret)

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

		mp.log.Printf("conn(%d) pipe\n", cid)

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
