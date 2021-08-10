package util

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
)

func PrettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func LoadCA(CAFile string) (*x509.CertPool, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}

	if CAFile != "" {
		customCACert, err := ioutil.ReadFile(CAFile)
		if err != nil {
			return nil, err
		}
		if ok := rootCAs.AppendCertsFromPEM(customCACert); !ok {
			return nil, fmt.Errorf("unable to append the provided CA file: %s", CAFile)
		}
		log.Printf("Added CA certificate %s.\n", CAFile)
		return rootCAs, nil
	}
	return rootCAs, nil
}

// Initiate the ssl handshake through a proxy
// step1. Establish HTTP tunnel with proxy via the CONNECT method
// step2. Do TLS handshake
func HandshakeProxy(server string, proxyURL *url.URL, tlsConfig *tls.Config) (err error) {
	// get a TCP connection with the proxy
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		return
	}
	defer conn.Close()

	// create a HTTP CONNECT request to remote server
	req, err := http.NewRequest("CONNECT", fmt.Sprintf("https://%s", server), nil)
	if err != nil {
		return
	}

	// add proxy authentication
	if proxyURL.User.String() != "" {
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String()))
		req.Header.Add("Proxy-Authorization", basicAuth)
	}

	// send the CONNECT request to proxy to establish a tunnel
	err = req.Write(conn)
	if err != nil {
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("non-200 response status from proxy server: ", resp.Status, "\n")
		return errors.New("non-200 status code returned from proxy")
	}

	log.Println("Succesfully established connection to proxy")
	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err != nil {
		return
	}

	return
}