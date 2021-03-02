package util

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
)

// a minimal implementation of SSL_CTX_load_verify_locations()
// first search the certificates in CAFile, then those in CAPath
func LoadVerifyLocations(CAFile string, CAPath string) (*x509.CertPool, error) {
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
	} else if CAPath != "" {
		files, err := ioutil.ReadDir(CAPath)
		if err != nil {
			return nil, err
		}
		appendAtLeastOneCA := false
		for _, file := range files {
			if file.IsDir() {
				// do not go into subdirectory
				continue
			}
			customCACert, err := ioutil.ReadFile(CAPath + "/" + file.Name())
			if err != nil {
				continue
			}
			if ok := rootCAs.AppendCertsFromPEM(customCACert); ok {
				log.Printf("Added CA certificate %s to the bundle.\n", file.Name())
				appendAtLeastOneCA = true
			}
		}

		if appendAtLeastOneCA {
			return rootCAs, nil
		}

		return nil, fmt.Errorf("could not read any certificate bundle in the provided CA path: %s", CAPath)
	}
	return nil, nil
}

// generate fibonacci sequence
func Fibonacci() func() int {
	x, y := 0, 1
	return func() int {
		x, y = y, x+y
		return x
	}
}