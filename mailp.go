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
			if err != nil {
				err = fmt.Errorf("load imap.tls cert fail: %w", err)
			} else {
				l, err = tls.Listen("tcp", mp.conf.Imap.Addr, &tls.Config{
					Certificates: []tls.Certificate{cert},
				})
				if err != nil {
					err = fmt.Errorf("tls.listen fail: %w", err)
				}
			}
		} else {
			l, err = net.Listen("tcp", mp.conf.Imap.Addr)
			if err != nil {
				err = fmt.Errorf("net.listen fail: %w", err)
			}
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

	// connLog == on|handshake ? (value) : nil
	var doLog *atomic.Bool
	if mp.conf.Imap.ConnLog == "on" || mp.conf.Imap.ConnLog == "handshake" {
		doLog = &atomic.Bool{}
		doLog.Store(true)
	}

	c_r := imap.NewReader(bufio.NewReader(newReaderWithMayPrefixWriter(c, "c> ", os.Stderr, doLog)))
	c_w := imap.NewWriter(bufio.NewWriter(newWriterWithMayPrefixWriter(c, "c< ", os.Stderr, doLog)))

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

handshake_client:
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

				continue handshake_client
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

			continue handshake_client
		}

		switch cmd.Name {
		case "CAPABILITY":
			(&responses.Capability{Caps: caps}).WriteTo(c_w)
			// TODO: fill info
			(&imap.StatusResp{
				Tag:  cmd.Tag,
				Type: imap.StatusRespOk,
			}).WriteTo(c_w)

			continue handshake_client

		case "LOGIN":
			loginCmd := &commands.Login{}
			loginCmd.Parse(cmd.Arguments)

			err := func() error {
				username := loginCmd.Username
				password := loginCmd.Password

				if user, ok := mp.conf.Imap.Users[username]; ok {
					if subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) == 1 {
						connUsername = username
						// set username for connect upstream
						return nil
					}
				}

				return fmt.Errorf("bad username or password")
			}()

			if err != nil {
				(&imap.StatusResp{
					Tag:  cmd.Tag,
					Type: imap.StatusRespNo,
					Info: err.Error(),
				}).WriteTo(c_w)

				// 鉴权失败，可以给Client多几次机会
				continue handshake_client
			}

			// 鉴权成功，接下来开始跟 upstream 对接
			(&imap.StatusResp{
				Tag:  cmd.Tag,
				Type: imap.StatusRespOk,
			}).WriteTo(c_w)

			break handshake_client

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
				continue handshake_client
			}

			// 鉴权成功，接下来开始跟 upstream 对接
			(&imap.StatusResp{
				Tag:  cmd.Tag,
				Type: imap.StatusRespOk,
			}).WriteTo(c_w)

			break handshake_client

		default:
			mp.log.Printf("todo cmd %s(%s)", cmd.Tag, cmd.Name)
			(&imap.StatusResp{
				Tag:  cmd.Tag,
				Type: imap.StatusRespBad,
				Info: fmt.Sprintf("unsupport command %s", cmd.Name),
			}).WriteTo(c_w)
		}

	}

	// handshake_upstream and pipe
	err := func() error {
		// mp.log.Printf("user %s", connUsername)
		connUpConf := mp.conf.Imap.Users[connUsername].Upstream

		addr := connUpConf.Addr

		mp.log.Printf("conn(%d) connect upstream: %s", cid, addr)

		c2, err := mp.d.Dial("tcp", addr)
		if err != nil {
			return err
		}

		var c3 net.Conn
		if connUpConf.Tls.Enabled {
			serverName, _, _ := net.SplitHostPort(addr)
			tlsConfig := &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: connUpConf.Tls.SkipVerify,
			}
			tlsc := tls.Client(c2, tlsConfig)
			if err := tlsc.Handshake(); err != nil {
				return err
			}
			c3 = tlsc
		} else {
			c3 = c2
		}
		defer c3.Close()

		mp.log.Printf("conn(%d) connect upstream: %s (ok)", cid, addr)

		c3_r := imap.NewReader(bufio.NewReader(newReaderWithMayPrefixWriter(c3, "s> ", os.Stderr, doLog)))
		c3_w := imap.NewWriter(bufio.NewWriter(newWriterWithMayPrefixWriter(c3, "s< ", os.Stderr, doLog)))

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
		username := connUpConf.Auth.Username
		password := connUpConf.Auth.Password
		mp.log.Printf("conn(%d) login upstream as %s", cid, username)

		var cmd *imap.Command

		switch connUpConf.Auth.Type {
		case "plain":
			mech, ir, err := sasl.NewPlainClient(username, username, password).Start()
			if err != nil {
				return err
			}
			cmdr := &commands.Authenticate{
				Mechanism:       mech,
				InitialResponse: ir,
			}
			cmd = cmdr.Command()

		case "xoauth2":
			mech, ir, err := NewXoauth2Client(username, password).Start()
			if err != nil {
				return err
			}
			cmdr := &commands.Authenticate{
				Mechanism:       mech,
				InitialResponse: ir,
			}
			cmd = cmdr.Command()

		default:
			return fmt.Errorf("upstream auth support plain, got %s", connUpConf.Auth.Type)
		}

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

		// TODO: use enum
		if mp.conf.Imap.ConnLog == "handshake" {
			doLog.Store(false)
		}

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

func newReaderWithMayPrefixWriter(c io.Reader, ch string, w io.Writer, doLog *atomic.Bool) io.Reader {
	if doLog == nil {
		return c
	}
	return io.TeeReader(c, newMayPrefixWriter(ch, w, doLog))
}
func newWriterWithMayPrefixWriter(c io.Writer, ch string, w io.Writer, doLog *atomic.Bool) io.Writer {
	if doLog == nil {
		return c
	}
	return io.MultiWriter(c, newMayPrefixWriter(ch, w, doLog))
}

type prefixWriter struct {
	w  io.Writer
	ch []byte
}

func (w *prefixWriter) Write(p []byte) (n int, err error) {
	w.w.Write(w.ch)
	return w.w.Write(p)
}

func newPrefixWriter(ch string, w io.Writer) io.Writer {
	return &prefixWriter{
		w:  w,
		ch: []byte(ch),
	}
}

type mayPrefixWriter struct {
	w  io.Writer
	ch []byte

	doWrite *atomic.Bool
}

func (w *mayPrefixWriter) Write(p []byte) (n int, err error) {
	if !w.doWrite.Load() {
		return len(p), nil
	}

	w.w.Write(w.ch)
	return w.w.Write(p)
}

func newMayPrefixWriter(ch string, w io.Writer, doWrite *atomic.Bool) io.Writer {
	if doWrite == nil {
		panic("newMayPrefixWriter: doLog can not be nil")
	}
	return &mayPrefixWriter{
		w:       w,
		ch:      []byte(ch),
		doWrite: doWrite,
	}
}
