package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/g3rk6/gopensslproxy"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()
	proxy := gopensslproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(gopensslproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *gopensslproxy.ProxyCtx) (*http.Request, *http.Response) {
		return req, nil
	})
	proxy.Verbose = *verbose
	log.Fatal(http.ListenAndServe(*addr, proxy))
}
