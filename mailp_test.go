package main

import (
	"bufio"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	Assert "github.com/stretchr/testify/require"

	"github.com/emersion/go-imap"
	imap_mem "github.com/emersion/go-imap/backend/memory"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-imap/server"
	"github.com/emersion/go-sasl"
)

var _ = assert.New

func Test_mailp(t *testing.T) {
	A := Assert.New(t)

	var err error

	imapt, err := testStartImapServer(":1233", 20*time.Millisecond, nil)
	if imapt != nil {
		defer imapt.Close()
	}
	A.NoError(err, "start imap fail")

	mailpAddr := "127.0.0.1:1234"

	conf := &MailpConf{}
	err = conf.Load(`
imap:
  addr: ":1234"
  users:
    abc:
      password: 123
      upstream:
        addr: 127.0.0.1:1233
        auth:
          type: plain
          username: username
          password: password
`)
	A.NoError(err, "load conf")

	mp, err := testStartMailp(conf, 20*time.Millisecond)
	if mp != nil {
		defer mp.Stop()
	}
	A.NoError(err, "start mp fail")

	for _, useLogin := range []bool{true, false} {
		name := "use_auth_plain"
		if useLogin {
			name = "use_login"
		}

		t.Run(name, func(t *testing.T) {
			testMailpBasic(t, mailpAddr, useLogin)
		})
	}

}

func Test_mailp_upstreamAuthXoauth2(t *testing.T) {
	A := Assert.New(t)

	var err error

	imapt, err := testStartImapServer(":1233", 20*time.Millisecond, nil)
	if imapt != nil {
		defer imapt.Close()
	}
	A.NoError(err, "start imap fail")

	mailpAddr := "127.0.0.1:1234"

	conf := &MailpConf{}
	err = conf.Load(`
imap:
  addr: ":1234"
  users:
    abc:
      password: 123
      upstream:
        addr: 127.0.0.1:1233
        auth:
          type: xoauth2
          username: username
          password: password
`)
	A.NoError(err, "load conf")

	mp, err := testStartMailp(conf, 20*time.Millisecond)
	if mp != nil {
		defer mp.Stop()
	}
	A.NoError(err, "start mp fail")

	testMailpBasic(t, mailpAddr, true)
}

func Test_mailpTls(t *testing.T) {
	A := Assert.New(t)

	var err error

	imapt, err := testStartImapServer(":1233", 20*time.Millisecond, nil)
	if imapt != nil {
		defer imapt.Close()
	}
	A.NoError(err, "start imap fail")

	mailpAddr := "127.0.0.1:1234"

	conf := &MailpConf{}
	err = conf.Load(`
imap:
  addr: ":1234"
  tls:
    enabled: true
    cert: mailp-test.cert
    key: mailp-test.key
  users:
    abc: {}
`)
	A.NoError(err, "load conf")

	mp, err := testStartMailp(conf, 20*time.Millisecond)
	if mp != nil {
		defer mp.Stop()
	}
	A.NoError(err, "start mp fail")

	c, err := net.Dial("tcp", mailpAddr)
	A.NoError(err, "tcp")
	defer c.Close()

	c2 := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
	err = c2.Handshake()
	A.NoError(err, "tls")

	A.Equal("CN=mailp-test.local", c2.ConnectionState().PeerCertificates[0].Subject.String(), "tls cert name")

	c2.SetDeadline(time.Now().Add(10 * time.Millisecond))

	r := bufio.NewReader(c2)
	line, isPrefix, err := r.ReadLine()
	A.NoError(err, "read greet")
	A.False(isPrefix, "read greet")
	A.Truef(strings.HasPrefix(string(line), "* OK"), "greet begin with * OK, got %s", string(line))
}

func Test_mailpUpstreamTls(t *testing.T) {
	A := Assert.New(t)

	var err error

	cert, err := tls.LoadX509KeyPair("mailp-test.cert", "mailp-test.key")
	A.NoError(err, "load cert")
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	imapt, err := testStartImapServer(":1233", 20*time.Millisecond, tlsConf)
	if imapt != nil {
		defer imapt.Close()
	}
	A.NoError(err, "start imap fail")

	mailpAddr := "127.0.0.1:1234"

	t.Run("skipVerify tls", func(t *testing.T) {
		A := Assert.New(t)

		conf := &MailpConf{}
		err = conf.Load(`
imap:
  addr: ":1234"
  users:
    abc:
      password: 123
      upstream:
        addr: 127.0.0.1:1233
        tls:
          enabled: true
          skipVerify: true
        auth:
          type: plain
          username: username
          password: password
`)
		A.NoError(err, "load conf")

		mp, err := testStartMailp(conf, 20*time.Millisecond)
		if mp != nil {
			defer mp.Stop()
		}
		A.NoError(err, "start mp fail")

		testMailpBasic(t, mailpAddr, true)
	})

	t.Run("default verify tls", func(t *testing.T) {
		A := Assert.New(t)

		conf := &MailpConf{}
		err = conf.Load(`
imap:
  addr: ":1234"
  users:
    abc:
      password: 123
      upstream:
        addr: 127.0.0.1:1233
        tls:
          enabled: true
        auth:
          type: plain
          username: username
          password: password
`)
		A.NoError(err, "load conf")

		mp, err := testStartMailp(conf, 20*time.Millisecond)
		if mp != nil {
			defer mp.Stop()
		}
		A.NoError(err, "start mp fail")

		c, err := client.Dial(mailpAddr)
		A.NoError(err, "client.New")
		defer c.Terminate() // TODO: err?

		caps, err := c.Capability()
		A.NoError(err, "c.caps()")
		// caps map[AUTH=PLAIN:true CAPABILITY:true IMAP4rev1:true LITERAL+:true SASL-IR:true]
		A.Contains(caps, "AUTH=PLAIN")
		A.Contains(caps, "SASL-IR")

		err = c.Login("abc", "1")
		A.Error(err, "login bad")

		err = c.Login("abc", "123")
		A.NoError(err, "login")

		_, err = c.Capability()
		A.Error(err, "c.caps() real")
		A.Contains(err.Error(), "imap: connection close", "c.caps() real")
	})
}

func testMailpBasic(t *testing.T, addr string, useLogin bool) {
	A := Assert.New(t)

	c, err := client.Dial(addr)
	A.NoError(err, "client.New")
	defer c.Terminate() // TODO: err?

	caps, err := c.Capability()
	A.NoError(err, "c.caps()")
	// caps map[AUTH=PLAIN:true CAPABILITY:true IMAP4rev1:true LITERAL+:true SASL-IR:true]
	A.Contains(caps, "AUTH=PLAIN")
	A.Contains(caps, "SASL-IR")

	if useLogin {
		err = c.Login("abc", "1")
	} else {
		err = c.Authenticate(sasl.NewPlainClient("abc", "abc", "1"))
	}
	A.Error(err, "login bad")

	if useLogin {
		err = c.Login("abc", "123")
	} else {
		err = c.Authenticate(sasl.NewPlainClient("abc", "abc", "123"))
	}
	A.NoError(err, "login")

	caps, err = c.Capability()
	A.NoError(err, "c.caps() real")
	// TODO: check real caps from test imap server
	t.Logf("real caps: %+v", caps)

	done := make(chan interface{})
	ch := make(chan *imap.MailboxInfo)
	mboxes := make([]*imap.MailboxInfo, 0, 100)
	mboxNames := make([]string, 0, 100)
	go func() {
		for mbox := range ch {
			mboxes = append(mboxes, mbox)
			mboxNames = append(mboxNames, mbox.Name)
		}
		done <- nil
	}()
	err = c.List("", "*", ch)
	<-done
	A.NoError(err, "real list")

	A.Contains(mboxNames, "INBOX")
}

func testStartImapServer(addr string, wait time.Duration, tlsConf *tls.Config) (*server.Server, error) {
	srv := server.New(imap_mem.New())
	srv.Addr = addr
	srv.AllowInsecureAuth = true
	srv.Debug = imap.NewDebugWriter(
		newPrefixWriter("t< ", os.Stderr),
		newPrefixWriter("t> ", os.Stderr),
	)
	srv.EnableAuth(Xoauth2, func(conn server.Conn) sasl.Server {
		return NewXoauth2Server(func(opts Xoauth2Options) *Xoauth2Error {
			user, err := srv.Backend.Login(conn.Info(), opts.Username, opts.Token)
			if err != nil {
				// TODO: err ?
				return &Xoauth2Error{
					Status:  "invalid_request",
					Schemes: "bearer",
				}
			}

			ctx := conn.Context()
			ctx.State = imap.AuthenticatedState
			ctx.User = user
			return nil
		})
	})
	if tlsConf != nil {
		srv.TLSConfig = tlsConf
	}

	startErrCh := make(chan error)
	go func() {
		var err error
		if tlsConf != nil {
			err = srv.ListenAndServeTLS()
		} else {
			err = srv.ListenAndServe()
		}

		startErrCh <- err
	}()

	select {
	case err := <-startErrCh:
		return srv, err

	case <-time.After(wait):
	}

	return srv, nil
}

func testStartMailp(conf *MailpConf, wait time.Duration) (*Mailp, error) {
	mp := &Mailp{conf: conf}

	startErrCh := make(chan error)
	go func() {
		err := mp.Start()
		startErrCh <- err
	}()

	select {
	case err := <-startErrCh:
		return mp, err

	case <-time.After(wait):
	}

	return mp, nil
}
