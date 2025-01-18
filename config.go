package main

import "gopkg.in/yaml.v3"

var ConfigSample = `
imap:
  addr: "ip:port"
  tls:
    enabled: true
    cert: "path"
    key: "path"
  users:
    <username>:
      password: "?"
      upstream:
        addr: "127.0.0.1:1233"
        tls:
          enabled: true
        auth:
         type: plain
         username: "?"
         password: "?"
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
	Tls   TlsServerConf
	Users map[string]ImapUserConf
}
type ImapUserConf struct {
	Username string
	Password string
	Upstream ImapUpstreamConf
}
type ImapUpstreamConf struct {
	Addr string
	Tls  TlsClientConf
	Auth ImapAuthConf
}
type ImapAuthConf struct {
	Type     string
	Username string
	Password string
}
type TlsServerConf struct {
	Enabled bool
	Cert    string
	Key     string
}
type TlsClientConf struct {
	Enabled bool
}
