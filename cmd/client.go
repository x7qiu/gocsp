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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	clientCmd.PersistentFlags().StringVar(&server, "server", "", "host:port")
	clientCmd.PersistentFlags().StringVarP(&proxy, "proxy", "x", "", "scheme://(user):(password)@host:port")
	clientCmd.PersistentFlags().StringVar(&CAFile, "cafile", "", "CAfile used to verify the cert chain")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// clientCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

var (
	server	string
	proxy 	string
	CAFile	string

	ErrNotValidated = errors.New("unable to validate any cert chain")

)

// ProxyFunc is used to simplify proxy detection and setting proxies in the client.
type ProxyFunc func(*http.Request) (*url.URL, error)

const gocspTimeOut = 10 * time.Second

// ConnectAndVerify does the following things:
// 1. Connect to host, initiate the ssl handshake process to get the cert chain from server
// 2. Triggers a callback function where we examine the revocation status of each cert
// 3. Goes over each cert, check its CRL or OCSP status
func connectAndVerify(cmd *cobra.Command, args []string) {

	// hostPort is not expected to have a scheme, so do not use url.Parse()
	serverHost, serverPort, err := net.SplitHostPort(server)
	if err != nil{
		log.Fatalf("Error parsing server: %s.\n", err.Error())
	}

	// parse proxy
	var proxyURL *url.URL
	if proxy == ""{
		proxyURL = nil
	}else{
		proxyURL, err = url.ParseRequestURI(proxy)
		if err != nil{
			log.Fatalf("Error parsing proxy: %s.\n", err.Error())
		}
	}

	//log.Println("debug:proxyURL:", util.PrettyPrint(proxyURL))

	// custom CA
	CA, err := util.LoadCA(CAFile)
	var tlsConfig = &tls.Config{
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return checkRevocation(proxyURL, verifiedChains)
		},
		RootCAs:    CA,
		ServerName: serverHost,
	}

	// Initiate TLS handshake to trigger the checkRevocation callback
	if proxyURL != nil{
		err = util.HandshakeProxy(fmt.Sprintf("%s:%s", serverHost, serverPort), proxyURL, tlsConfig)
	} else {
		_, err = tls.Dial("tcp", fmt.Sprintf("%s:%s", serverHost, serverPort), tlsConfig)
	}

	return
}

// VerifyPeerCertificate specifies a callback function that is called after Go does its normal verification on the cert chain(aka rawCerts) sent from peer.
// "Go's normal verification" is just an implicitly-called x509.Certificate.Verify(). It does not check revocation status. It can be disabled, but makes no sense to do so for OCSP.
// If normal verification fails(wrong hostname, cert expired, etc), the handshake process aborts and the callback function would not be invoked.
// rawCerts: the cert chain that's sent from the peer.
// verifiedChains: the result of applying x509.Certificate.Verify() on rawCerts.
func checkRevocation(proxyURL *url.URL, verifiedChains [][]*x509.Certificate) (err error) {
	log.Println("Starting certificate validation.")

	for _, chain := range verifiedChains {
		for i, cert := range chain {
			var nextCert *x509.Certificate

			certName := fmt.Sprintf("Cert #%d", i+1)
			log.Printf("%s: Checking revocation status.\n", certName)
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

			err = isCertRevoked(cert, nextCert, proxyURL, certName)
			if err != nil {
				log.Printf("Warning: %s failed to verify revocation status: %s. Trying the next chain if there is one.\n", certName, err.Error())
				break
			} else {
				log.Printf("%s: OK.\n", certName)
			}
		}
	}
	return ErrNotValidated
}

// Check if a cert is revoked. It is considered valid if 1) CRL check passes 2) CRL is empty and OCSP check passes
func isCertRevoked(cert *x509.Certificate, issuer *x509.Certificate, proxyURL *url.URL, certName string) error {
	log.Println("debug:proxyURL:", util.PrettyPrint(proxyURL))
	// CRL check; multiple CRL points for a single cert is possible; we only check the first one for now
	for _, CDP := range cert.CRLDistributionPoints {
		crl, err := fetchCRL(CDP, proxyURL)
		if err != nil {
			return err
		}

		err = issuer.CheckCRLSignature(crl)
		if err != nil {
			return err
		}

		for _, revoked := range crl.TBSCertList.RevokedCertificates {
			if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				log.Println("Found a match on CRL. This certificate has been revoked.\n")
				return errors.New("revoked")
			}
		}
		// CRL check passed. Skipping OCSP checks.
		return nil
	}

	// If no CRL and no OCSP server, fail.
	if len(cert.OCSPServer) == 0 {
		return errors.New("no OCSP server found. This is likely a self-signed certificate used by a proxy or firewall for TLS inspection")
	}

	// multiple OCSP servers for a single cert is possible; we only check the first one for now
	for _, ocspServer := range cert.OCSPServer {
		return checkOCSP(cert, issuer, ocspServer, proxyURL)
	}

	// shouldn't ever reach here
	return nil
}

// fetch and parse CRL
func fetchCRL(url string, proxyURL *url.URL) (*pkix.CertificateList, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: gocspTimeOut,
	}

	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL")
	}

	bytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return x509.ParseCRL(bytes)
}

// check the OCSP status of a specific cert
func checkOCSP(cert *x509.Certificate, issuer *x509.Certificate, ocspServer string, proxyURL *url.URL) error {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: gocspTimeOut,
	}

	buffer, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{})
	if err != nil {
		return err
	}

	OCSPRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(buffer))
	if err != nil {
		return err
	}
	OCSPRequest.Header.Add("Content-Type", "application/ocsp-request")
	OCSPRequest.Header.Add("Accept", "application/ocsp-response")

	response, err := client.Do(OCSPRequest)
	if err, ok := err.(net.Error); ok && err.Timeout() { // a timeout error
		return errors.New(fmt.Sprintf("connection timed out after %ds", gocspTimeOut/time.Second))
	} else if err != nil { // non-timeout error
		return err
	}

	defer response.Body.Close()

	output, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	ocspResponse, err := ocsp.ParseResponse(output, issuer)
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
}
