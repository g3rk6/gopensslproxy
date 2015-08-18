package gopensslproxy

import (
	"crypto/sha1"
	"math/big"
	"math/rand"
	"net"
	"sort"
	"time"

	"github.com/g3rk6/openssl"
)

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha1.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	return h.Sum(nil)
}

func hashSortedBigInt(lst []string) *big.Int {
	rv := new(big.Int)
	rv.SetBytes(hashSorted(lst))
	return rv
}

func issueCert(hosts []string) (*openssl.Certificate, *openssl.PrivateKey, error) {

	privKey, _ := openssl.GenerateRSAKey(1024)

	der, _ := privKey.MarshalPKIXPublicKeyDER()
	pubKey, _ := openssl.LoadPublicKeyFromDER(der)

	// Use a clone of serverCert certificate as a template.
	cert, err := openssl.LoadCertificateFromPEM(serverCert)
	if err != nil {
		return nil, nil, err
	}

	// New certificate validity is always 11 days which means
	// it has issued yesterday (-24) and expire in 10 days (240).
	cert.SetIssueDate(time.Duration(-24) * time.Hour)
	cert.SetExpireDate(time.Duration(240) * time.Hour)

	// Replace existing public key with new key
	cert.SetPubKey(pubKey)

	// Generate new name
	name, _ := openssl.NewName()
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			name.AddTextEntry("CN", ip.String())
		} else {
			name.AddTextEntry("CN", h)
		}
	}
	name.AddTextEntry("O", "Man Cave, LLC")
	name.AddTextEntry("OU", "Fun")

	// Replace existing name with new name
	cert.SetSubjectName(name)

	// Update existing serial with unique one
	rand.Seed(time.Now().UnixNano())
	serial := rand.Int()
	cert.SetSerial(serial)

	// Load Root CA private key and sign new certificate
	caPrivKey, _ := openssl.LoadPrivateKeyFromPEM(rootKeyCA)
	cert.Sign(caPrivKey, openssl.EVP_SHA256)

	return cert, &privKey, err
}
