package main

import (
	"flag"
	"io"
	"os"
	"strings"
)

func main() {
	var err error

	configPath := flag.String("c", "", "config file")
	dump := flag.Bool("d", false, "dump config file")

	flag.Parse()

	if *dump {
		io.Copy(os.Stdout, strings.NewReader(ConfigSample))
		return
	}

	if *configPath == "" {
		os.Stderr.WriteString("-c is required")
		os.Exit(1)
	}

	conf := &MailpConf{}
	{
		var cs []byte
		cs, err = os.ReadFile(*configPath)
		if err == nil {
			err = conf.Load(string(cs))
		}
	}
	if err != nil {
		panic(err)
	}

	mp := &Mailp{conf: conf}

	err = mp.Start()
	if err != nil {
		panic(err)
	}

}
