package main

import (
	"fmt"
	"net"
	"os"
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

func Test_mailp(t *testing.T) {
	a := assert.New(t)
	_ = a
	A := Assert.New(t)
	_ = A

	var err error

	go runTestImapServer(":1233")
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

	go mailp(conf)
	time.Sleep(20 * time.Millisecond)

	c, err := client.Dial(mailpAddr)

	A.NoError(err, "client.New")

	caps, err := c.Capability()
	A.NoError(err, "c.caps()")
	// caps map[AUTH=PLAIN:true CAPABILITY:true IMAP4rev1:true LITERAL+:true SASL-IR:true]
	A.Contains(caps, "AUTH=PLAIN")
	A.Contains(caps, "SASL-IR")

	err = c.Authenticate(sasl.NewPlainClient("abc", "abc", "1"))
	A.Error(err, "login bad")
	err = c.Authenticate(sasl.NewPlainClient("abc", "abc", "123"))
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

	// time.Sleep(200 * time.Millisecond)
	// t.Fatal("TBD")
}

func runTestImapServer(addr string) error {
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
