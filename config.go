package main

import "gopkg.in/yaml.v3"

var _ = `
imap:
  addr: "ip:port"
  tls: ?
  users:
    <username>:
      password: ?
      upstream:
        addr: 127.0.0.1:1233
        auth:
         type: plain
         username: ?
         password: ?
`

type MailpConf struct {
	Imap ImapConf
}

func (c *MailpConf) Load(s string) error {
	return yaml.Unmarshal([]byte(s), c)
}

type ImapConf struct {
	// server listen
	Addr  string
	Tls   string
	Users map[string]ImapUserConf
}
type ImapUserConf struct {
	Username string
	Password string
	Upstream ImapUpstreamConf
}
type ImapUpstreamConf struct {
	Addr string
	Auth ImapAuthConf
}
type ImapAuthConf struct {
	Type     string
	Username string
	Password string
}
