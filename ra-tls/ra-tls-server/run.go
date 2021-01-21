package main // import "github.com/inclavare-containers/inclavared"

/*
#cgo CFLAGS: -I../build/include
#cgo LDFLAGS: -L../build/lib -lenclave-tls -lm

#include <stdbool.h>
 #include "enclave-tls.h"

extern int ra_tls_server_startup(int sockfd, quote_type_t quote_type, bool mutual, bool debug);
*/
import "C"
import (
	"fmt"
	"github.com/urfave/cli"
	"net"
	"strings"
	"syscall"
)

const (
	defaultAddress = "/run/rune/ra-tls.sock"
)

var runCommand = cli.Command{
	Name:  "run",
	Usage: "run the inclavared",
	ArgsUsage: `[command options]

EXAMPLE:

       # shelterd-shim-agent run &`,
	Flags: []cli.Flag{
		/*
			cli.IntFlag{
				Name:        "port",
				Value:       listeningPort,
				Usage:       "listening port for receiving external requests",
				Destination: &listeningPort,
			},
		*/
		cli.StringFlag{
			Name:  "addr",
			Usage: "the timeout in second for re-establishing the connection to inclavared",
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

		syscall.Unlink(addr)

		ln, err := net.Listen("unix", addr)
		if err != nil {
			return err
		}
		defer ln.Close()

		unixListener, ok := ln.(*net.UnixListener)
		if !ok {
			return fmt.Errorf("casting to UnixListener failed")
		}

		unixListener.SetUnlinkOnClose(false)
		defer unixListener.SetUnlinkOnClose(true)

		c, err := unixListener.Accept()
		if err != nil {
			return err
		}
		defer c.Close()

		conn, ok := c.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed")
		}

		connFile, err := conn.File()
		if err != nil {
			return err
		}
		defer connFile.Close()

		C.ra_tls_server_startup(C.int(connFile.Fd()), C.quote_type_t(quoteType), C.bool(mutual), C.bool(debug))

		return nil
	},
}
