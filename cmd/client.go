/*
Copyright © 2021 Xie Qiu <qiux0518@hotmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/qiux0518/gocsp/util"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)


// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: connectAndVerify,
}

func init() {
	rootCmd.AddCommand(clientCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	clientCmd.PersistentFlags().StringVar(&hostPort, "host", "", "host:port")
	clientCmd.PersistentFlags().StringVarP(&proxyStr, "proxy", "x", "", "scheme://(user):(password)@host:port")
	clientCmd.PersistentFlags().StringVar(&CAFile, "cafile", "", "CAfile used to verify the OCSP response")
	clientCmd.PersistentFlags().StringVar(&CAPath, "capath", "", "Directoray containing CAfile used to verify the OCSP response")
	clientCmd.PersistentFlags().BoolVar(&dryRun, "dry", false, "Dry run")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// clientCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

var (
	hostPort	string
	proxyStr 	string
	CAFile		string
	CAPath		string
	dryRun		bool

	// ErrOCSPNotVerified cannot be retried
	ErrOCSPNotVerified = errors.New("unable to verify any certificate chain")

	// ErrProxyNotAvailable cannot be retried
	ErrProxyNotAvailable = errors.New("unable to establish connection to proxy")
)

// ProxyFunc is used to simplify proxy detection and setting proxies in the client.
type ProxyFunc func(*http.Request) (*url.URL, error)

const maxConAttempts = 5
const ocspSoftFailTimeOut = 5 * time.Second
const ocspHardFailTimeOut = 15 * time.Second

// ConnectAndVerify does 2 things:
// 1. Connect to host, initiate the ssl handshake process to get the cert chain from server which triggers a callback function where we examine the revocation status of each cert
// 2. Goes over each cert, sends an OCSP request to the corresponding OCSP server to check the revocation status
func connectAndVerify(cmd *cobra.Command, args []string) {

	// hostPort is not expected to have a scheme, so do not use url.Parse()
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil{
		log.Fatalf("Error parsing host: %s.\n", err.Error())
	}

	proxyURL, err := url.Parse(proxyStr)
	if err != nil{
		log.Fatalf("Error parsing proxy: %s.\n", err.Error())
	}

	var proxyHostPort = proxyURL.Host
	var proxyFunc ProxyFunc
	if proxyHostPort != ""{
		proxyFunc = http.ProxyURL(proxyURL)
	} else{
		proxyFunc = nil		// http.ProxyURL is not smart enough to do this on an empty string
	}

	rootCAs, err := util.LoadVerifyLocations(CAFile, CAPath)
	if err != nil {
		log.Printf("Error loading custom CA: %s. Using system default CAs instead.\n", err.Error())
		// If RootCAs is nil, TLS uses the host's root CA set
		rootCAs = nil
	}

	var tlsConfig = &tls.Config{
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return checkOCSP(proxyFunc, dryRun, verifiedChains)
		},
		RootCAs:    rootCAs,
		ServerName: host, 	// google.com
	}

	// handshake with the host to trigger the callback
	attempt := 0
	fib := util.Fibonacci()

	for attempt < maxConAttempts {
		if proxyHostPort != "" {
			err = handshakeProxy(host, port, proxyURL, tlsConfig)
		} else {
			_, err = tls.Dial("tcp", fmt.Sprintf("%s:%s", host, port), tlsConfig)
		}

		// If if's an OCSP error, we return immediately, as retrying would not change the outcome
		if err == ErrOCSPNotVerified || err == ErrProxyNotAvailable {
			log.Fatalf("Irrecoverable error: %s.\n", err.Error())
		}

		if err == nil{
			return
		}
		// otherwise, it's possible that KGP server is not ready yet. Retries handshake
		log.Printf("Warning: Something went wrong before we reached the OCSP step: ", err, ". This may be recoverable, retrying...\n")
		sleep := fib() // 1, 1, 2, 3, 5, etc
		log.Printf("Sleeping for ", sleep, " seconds.\n")
		time.Sleep(time.Duration(sleep) * time.Second)
		attempt++
	}
	return
}

// Initiate the ssl handshake through a proxy
func handshakeProxy(host string, port string, proxyURL *url.URL, tlsConfig *tls.Config) (err error) {
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		return
	}
	defer conn.Close()

	req, err := http.NewRequest("CONNECT", fmt.Sprintf("https://%s:%s", host, port), nil)
	if err != nil {
		return
	}

	if proxyURL.User.String() != "" {
		basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String()))
		req.Header.Add("Proxy-Authorization", basicAuth)
	}

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
		return ErrProxyNotAvailable
	}
	log.Println("Succesfully established connection to proxy")
	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	err = tlsConn.Handshake() // implicitly calls checkOCSP()
	if err != nil {
		return
	}

	return
}

// VerifyPeerCertificate specifies a callback function that is called after Go does its normal verification on the cert chain(aka rawCerts) sent from peer.
// "Go's normal verification" is just an implicitly-called x509.Certificate.Verify(). It does not check revocation status. It can be disabled, but makes no sense to do so for OCSP.
// If normal verification fails(wrong hostname, cert expired, etc), the handshake process aborts and the callback function would not be invoked.
// rawCerts: the cert chain that's sent from the peer.
// verifiedChains: the result of applying x509.Certificate.Verify() on rawCerts.
func checkOCSP(proxyFunc ProxyFunc, dryRun bool, verifiedChains [][]*x509.Certificate) (err error) {
	log.Println("Starting OCSP certificate check.")

	for _, chain := range verifiedChains {
		for i, cert := range chain {
			var nextCert *x509.Certificate

			certName := fmt.Sprintf("Cert #%d", i+1)
			log.Printf("%s: Checking OCSP status.\n", certName)
			log.Printf("%s Subject: %s\n", certName, cert.Subject)
			log.Printf("%s Issuer: %s\n", certName, cert.Issuer)

			if i+1 < len(chain) {
				nextCert = chain[i+1]
			} else if cert.IsCA {
				log.Println("Reached a trusted CA. Certificate chain is verified.")
				return nil // we found one good chain. This is the only place a good cert chain should return
			} else {
				log.Println("Warning: CA certificate is missing from the current certificate chain. Trying the next chain if there is one.")
				break
			}

			if !cmp.Equal(cert.Issuer, nextCert.Subject) {
				log.Println("Warning: Certificate chain is in the incorrect order. There might be a server configuration problem. Trying the next chain if there is one.")
				break
			}

			err = isCertRevoked(cert, nextCert, proxyFunc, dryRun, certName)
			if err != nil {
				log.Printf("Warning: %s failed to verify revocation status: %s Trying the next chain if there is one.\n", certName, err.Error())
				break
			} else {
				log.Printf("%s: OK.\n", certName)
			}
		}
	}
	return ErrOCSPNotVerified
}

// Check if a cert is revoked. If there are multiple OCSP servers, it is considered valid if any OCSP server can validate it.
func isCertRevoked(cert *x509.Certificate, issueCert *x509.Certificate, proxyFunc ProxyFunc, dryRun bool, certName string) error {
	var OCSPTimeOut time.Duration
	if dryRun {
		OCSPTimeOut = ocspSoftFailTimeOut
	} else  {
		OCSPTimeOut = ocspHardFailTimeOut
	}

	// OCSP would fail if behind a TLS inspecting proxy
	if len(cert.OCSPServer) == 0 {
		return errors.New("no OCSP server found. This is likely a self-signed certificate used by a proxy or firewall for TLS inspection")
	}

	for _, ocspServer := range cert.OCSPServer {
		err := func() error { // use an anonymous function so that the return value is easy to manager and defer() wouldn't be in a loop
			client := &http.Client{
				Transport: &http.Transport{
					Proxy: proxyFunc,
				},
				Timeout: OCSPTimeOut,
			}

			buffer, err := ocsp.CreateRequest(cert, issueCert, &ocsp.RequestOptions{})
			if err != nil {
				return err
			}

			OCSPRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
			if err != nil {
				return err
			}
			OCSPRequest.Header.Add("Content-Type", "application/ocsp-request")
			OCSPRequest.Header.Add("Accept", "application/ocsp-response")

			// no need to set basic auth again. Why?
			response, err := client.Do(OCSPRequest)
			if err, ok := err.(net.Error); ok && err.Timeout() { // a timeout error
				return errors.New(fmt.Sprintf("connection timed out after %ds", OCSPTimeOut/time.Second))
			} else if err != nil { // non-timeout error
				return err
			}

			defer response.Body.Close()

			output, err := ioutil.ReadAll(response.Body)
			if err != nil {
				return err
			}

			ocspResponse, err := ocsp.ParseResponse(output, issueCert)
			if err != nil {
				return err
			}

			if ocspResponse.Status == ocsp.Revoked {
				return errors.New("revoked")
			}

			if ocspResponse.Status != ocsp.Good {
				return errors.New("revocation status unknown")
			}
			return nil
		}()
		// check the returned err of above anonymous function
		if err == nil{
			return nil
		} else if dryRun{
			log.Printf("Warning: %s verification failed on %s: Error: %s. Ignore this error and continue in dry-run mode.\n", certName, ocspServer, err.Error())
			return nil
		} else{
			log.Printf("Warning: %s verification failed on %s: Error: %s. Trying the next OCSP server if there is one.\n", certName, ocspServer, err.Error())
		}
	}
	return errors.New("unable to verify on any OCSP server.")
}