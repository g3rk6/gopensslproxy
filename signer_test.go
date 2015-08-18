package gopensslproxy

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	// "github.com/g3rk6/gopensslproxy/transport"
	"github.com/g3rk6/openssl"
)

func orFatal(msg string, err error, t *testing.T) {
	if err != nil {
		t.Fatal(msg, err)
	}
}

type ConstantHanlder string

func (h ConstantHanlder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h))
}

func getBrowser(args []string) string {
	for i, arg := range args {
		if arg == "-browser" && i+1 < len(arg) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "-browser=") {
			return arg[len("-browser="):]
		}
	}
	return ""
}

func TestSignerTLS(t *testing.T) {

	// Issue a certificate using OpenSSL
	newCert, newKey, err := issueCert([]string{"mancave.local", "1.1.1.1", "localhost"})
	orFatal("issueCert", err, t)

	_, err = openssl.LoadCertificateFromPEM(serverCert)
	orFatal("ParseTemplateCertificateTLS", err, t)

	_, err = openssl.LoadCertificateFromPEM(rootCertCA)
	orFatal("ParseCACertificateTLS", err, t)

	expected := "key verifies with Go"

	certpool := x509.NewCertPool()
	certpool.AddCert(GopenSSLProxyCA.Leaf)

	// Go's built-in tranport works just fine.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certpool},
	}

	// OpenSSL based transport which crashes on FreeBSD
	// tlsConfig, err := openssl.NewCtx()
	// tr := &transport.Transport{
	// 	TLSClientConfig: tlsConfig,
	// }

	srv := &http.Server{
		// Addr:    ":8443",
		Handler: ConstantHanlder(expected),
	}

	sslCtx, err := openssl.NewCtx()
	orFatal("NewContext", err, t)
	sslCtx.UseCertificate(newCert)
	sslCtx.UsePrivateKey(*newKey)

	l, err := openssl.Listen("tcp", ":8443", sslCtx)
	orFatal("NewListener", err, t)

	go srv.Serve(l)

	// Making sure to wait long enough
	// until the server start listening
	time.Sleep(2 * time.Second)

	req, err := http.NewRequest("GET", "https://localhost:8443", nil)
	orFatal("NewRequest", err, t)

	resp, err := tr.RoundTrip(req)
	orFatal("RoundTrip", err, t)

	txt, err := ioutil.ReadAll(resp.Body)
	orFatal("ioutil.ReadAll", err, t)
	if string(txt) != expected {
		t.Errorf("Expected '%s' got '%s'", expected, string(txt))
	}
}

func TestSignerX509(t *testing.T) {

	newIssuedCert, _, err := issueCert([]string{"example.com", "1.1.1.1", "localhost"})
	orFatal("issueCert", err, t)

	newIssuedCertPEM, err := newIssuedCert.MarshalPEM()
	orFatal("MarshalPEM", err, t)

	_, err = openssl.LoadCertificateFromPEM(newIssuedCertPEM)
	orFatal("ParseTemplateCertificateX509", err, t)
}

func GetServerCert() []byte {
	return serverCert
}

func GetServerKey() []byte {
	return serverKey
}
