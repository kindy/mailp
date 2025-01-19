package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-sasl"
)

const Xoauth2 = "XOAUTH2"

// An XOAUTH2 error.
type Xoauth2Error struct {
	Status  string `json:"status"`
	Schemes string `json:"schemes"`
	Scope   string `json:"scope"`
}

// Implements error.
func (err *Xoauth2Error) Error() string {
	return fmt.Sprintf("XOAUTH2 authentication error (%v)", err.Status)
}

// copy from aerc/lib
type xoauth2Client struct {
	Username string
	Token    string
}

func (a *xoauth2Client) Start() (mech string, ir []byte, err error) {
	mech = Xoauth2
	ir = []byte("user=" + a.Username + "\x01auth=Bearer " + a.Token + "\x01\x01")
	return
}

func (a *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	// Server sent an error response
	xoauth2Err := &Xoauth2Error{}
	if err := json.Unmarshal(challenge, xoauth2Err); err != nil {
		return nil, err
	} else {
		return nil, xoauth2Err
	}
}

// An implementation of the XOAUTH2 authentication mechanism, as
// described in https://developers.google.com/gmail/xoauth2_protocol.
func NewXoauth2Client(username, token string) sasl.Client {
	return &xoauth2Client{username, token}
}

type Xoauth2Options struct {
	Username string
	Token    string
}

type Xoauth2Authenticator func(opts Xoauth2Options) *Xoauth2Error

// copy from sasl.oauthbear
type xoauth2Server struct {
	done         bool
	failErr      error
	authenticate Xoauth2Authenticator
}

func (a *xoauth2Server) fail(descr string) ([]byte, bool, error) {
	blob, err := json.Marshal(Xoauth2Error{
		Status:  "invalid_request",
		Schemes: "bearer",
	})
	if err != nil {
		panic(err) // wtf
	}
	a.failErr = errors.New("sasl: client error: " + descr)
	return blob, false, nil
}

func (a *xoauth2Server) Next(response []byte) (challenge []byte, done bool, err error) {
	if a.failErr != nil {
		if len(response) != 1 && response[0] != 0x01 {
			return nil, true, errors.New("sasl: invalid response")
		}
		return nil, true, a.failErr
	}

	if a.done {
		err = sasl.ErrUnexpectedClientResponse
		return
	}

	if response == nil {
		return []byte{}, false, nil
	}

	a.done = true

	opts := Xoauth2Options{}

	// Cut "user=" + a.Username + "\x01auth=Bearer " + a.Token + "\x01\x01"
	// into
	//   user=...
	//   auth=...
	//   *empty*
	params := bytes.Split(response, []byte{0x01})
	for _, p := range params {
		// Skip empty fields
		if len(p) == 0 {
			continue
		}

		pParts := bytes.SplitN(p, []byte{'='}, 2)
		if len(pParts) != 2 {
			return a.fail("Invalid response, missing '='")
		}

		switch string(pParts[0]) {
		case "user":
			opts.Username = string(pParts[1])
		case "auth":
			const prefix = "bearer "
			strValue := string(pParts[1])
			// Token type is case-insensitive.
			if !strings.HasPrefix(strings.ToLower(strValue), prefix) {
				return a.fail("Unsupported token type")
			}
			opts.Token = strValue[len(prefix):]
		default:
			return a.fail("Invalid response, unknown parameter: " + string(pParts[0]))
		}
	}

	authzErr := a.authenticate(opts)
	if authzErr != nil {
		blob, err := json.Marshal(authzErr)
		if err != nil {
			panic(err) // wtf
		}
		a.failErr = authzErr
		return blob, false, nil
	}

	return nil, true, nil
}

func NewXoauth2Server(auth Xoauth2Authenticator) sasl.Server {
	return &xoauth2Server{authenticate: auth}
}
