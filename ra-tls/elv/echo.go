package main

/*
#cgo CFLAGS: -I../build/include
#cgo LDFLAGS: -L../build/lib -lenclave-tls -lm

#include <stdbool.h>
#include "enclave-tls.h"

extern int ra_tls_echo(int sockfd, quote_type_t quote_type, bool mutual, bool debug);
*/
import "C"
import (
	"fmt"
	"github.com/urfave/cli"
	"net"
	"strings"
)

const (
	defaultAddress = "/run/rune/ra-tls.sock"
)

var echoCommand = cli.Command{
	Name:  "echo",
	Usage: "echo the message",
	ArgsUsage: `[command options]

EXAMPLE:

       # shelter attest foo.com`,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "addr",
			Usage: "ra-tls server address",
		},
		cli.StringFlag{
			Name:  "port",
			Usage: "ra-tls server port",
		},
		cli.StringFlag{
			Name:  "quote-type",
			Usage: "specify the quote type such as epid and ecdsa",
		},
		cli.BoolFlag{
			Name:  "mutual",
			Usage: "Enable mutual enclave TLS. Disabled by default.",
		},
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Enable debug mode. Disabled by default.",
		},
	},
	SkipArgReorder: true,
	Action: func(cliContext *cli.Context) error {
		quoteType := 0
		if strings.EqualFold(cliContext.String("quote-type"), "epid") {
			quoteType = C.QUOTE_TYPE_EPID
		}

		mutual := false
		if cliContext.Bool("mutual") {
			mutual = true
		}

		debug := false
		if cliContext.Bool("debug") {
			debug = true
		}

		addr := cliContext.String("addr")
		if addr == "" {
			addr = defaultAddress
		}

		conn, err := net.Dial("unix", addr)
		if err != nil {
			return err
		}
		defer conn.Close()

		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed")
		}

		sockfd, err := unixConn.File()
		if err != nil {
			return err
		}

		C.ra_tls_echo(C.int(sockfd.Fd()), C.quote_type_t(quoteType), C.bool(mutual), C.bool(debug))
		return nil
	},
}
