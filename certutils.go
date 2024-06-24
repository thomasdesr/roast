package roast

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/thomasdesr/roast/internal/errorutil"
)

type caBundle struct {
	priv *ecdsa.PrivateKey
	cert *x509.Certificate

	certPEM []byte
}

func makeLocalCA() (*caBundle, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errorutil.Wrap(err, "generate keys")
	}

	template := baseX509Cert()
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign
	template.BasicConstraintsValid = true

	// Self-sign ourselves
	certDERBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, errorutil.Wrap(err, "create certificate")
	}

	x509Cert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		return nil, errorutil.Wrap(err, "parsing the cert we just created")
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes})
	if certPEM == nil {
		return nil, fmt.Errorf("encode cert pem")
	}

	return &caBundle{
		cert: x509Cert,
		priv: priv,

		certPEM: certPEM,
	}, nil
}

func baseX509Cert() *x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24),
	}

	return template
}

type clientHello struct {
	ClientCA        []byte   // PEM-encoded
	ServerHostnames []string // DNS names or IP addresses
}

func makeServerConfig(localCA caBundle, ch clientHello) (*tls.Config, error) {
	serverCert, err := generateServerCert(localCA, ch.ServerHostnames)
	if err != nil {
		return nil, errorutil.Wrap(err, "generate server cert")
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(ch.ClientCA) {
		return nil, fmt.Errorf("append client CA")
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,

		MinVersion: tls.VersionTLS13,
	}

	return serverConfig, nil
}

func generateServerCert(localCA caBundle, serverHostnames []string) (*tls.Certificate, error) {
	serverCertTemplate := baseX509Cert()
	serverCertTemplate.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	serverCertTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	// Set the appropriate DNS names and IP addresses on the template
	for _, h := range serverHostnames {
		if ip := net.ParseIP(h); ip != nil {
			serverCertTemplate.IPAddresses = append(serverCertTemplate.IPAddresses, ip)
		} else {
			serverCertTemplate.DNSNames = append(serverCertTemplate.DNSNames, h)
		}
	}

	serverPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errorutil.Wrap(err, "generate server keys")
	}

	serverCertDER, err := x509.CreateCertificate(
		rand.Reader,
		serverCertTemplate,
		localCA.cert,
		&serverPriv.PublicKey,
		localCA.priv,
	)
	if err != nil {
		return nil, errorutil.Wrap(err, "create server cert")
	}

	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		return nil, errorutil.Wrap(err, "parse server cert")
	}

	return &tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverPriv,
		Leaf:        serverCert,
	}, nil
}

type serverHello struct {
	ServerCA []byte // PEM-encoded
}

func makeClientConfig(localCA caBundle, hostname string, sh serverHello) (*tls.Config, error) {
	clientCert, err := generateClientCert(localCA)
	if err != nil {
		return nil, errorutil.Wrap(err, "generate client cert")
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(sh.ServerCA) {
		return nil, fmt.Errorf("append server CA")
	}

	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		RootCAs:      caCertPool,

		// Who are we talking to? This should be the hostname of the server
		ServerName: hostname,

		MinVersion: tls.VersionTLS13,
	}

	return clientConfig, nil
}

func generateClientCert(localCA caBundle) (*tls.Certificate, error) {
	clientCertTemplate := baseX509Cert()
	clientCertTemplate.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	clientCertTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	// TODO: Figure out if we should use some sort of local name for the client cert
	clientPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errorutil.Wrap(err, "generate client keys")
	}

	clientCertDER, err := x509.CreateCertificate(
		rand.Reader,
		clientCertTemplate,
		localCA.cert,
		&clientPriv.PublicKey,
		localCA.priv,
	)
	if err != nil {
		return nil, errorutil.Wrap(err, "create client cert")
	}

	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		return nil, errorutil.Wrap(err, "parse client cert")
	}

	return &tls.Certificate{
		Certificate: [][]byte{clientCertDER},
		PrivateKey:  clientPriv,
		Leaf:        clientCert,
	}, nil
}
