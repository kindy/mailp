package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
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

var mu sync.Mutex

func Test_mailp(t *testing.T) {
	mu.Lock()
	defer mu.Unlock()

	A := Assert.New(t)

	var err error

	// FIXME: stop it
	go testStartImapServer(":1233")
	time.Sleep(20 * time.Millisecond)

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

	_, err, clean := testStartMailp(conf, 20*time.Millisecond)
	if clean != nil {
		defer func() {
			A.NoError(clean(), "stop")
		}()
	}
	A.NoError(err, "start mp fail")

	for _, useLogin := range []bool{true, false} {
		name := "use_auth_plain"
		if useLogin {
			name = "use_login"
		}

		t.Run(name, func(t *testing.T) {
			A := Assert.New(t)

			c, err := client.Dial(mailpAddr)
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
		})
	}

}

func Test_mailpTls(t *testing.T) {
	mu.Lock()
	defer mu.Unlock()

	A := Assert.New(t)

	var err error

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

	_, err, clean := testStartMailp(conf, 20*time.Millisecond)
	if clean != nil {
		defer func() {
			A.NoError(clean(), "stop")
		}()
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

func testStartImapServer(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}

	fmt.Printf("listing on %s\n", l.Addr().String())

	srv := server.New(imap_mem.New())

	srv.AllowInsecureAuth = true
	srv.Debug = imap.NewDebugWriter(
		newPrefixWriter("t< ", os.Stderr),
		newPrefixWriter("t> ", os.Stderr),
	)

	return srv.Serve(l)
}

func testStartMailp(conf *MailpConf, wait time.Duration) (*Mailp, error, func() error) {
	var mp *Mailp
	var clean func() error

	{
		startErrCh := make(chan error)
		go func() {
			mp = &Mailp{conf: conf}
			clean = mp.Stop
			err := mp.Start()
			startErrCh <- err
		}()

		select {
		case err := <-startErrCh:
			return mp, err, clean

		case <-time.After(wait):
		}
	}

	return mp, nil, clean
}
