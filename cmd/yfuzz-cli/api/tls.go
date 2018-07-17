// Copyright 2018 Oath, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package api

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"

	"github.com/fatih/color"
	"github.com/spf13/viper"
)

// newClient creates a http client for requests, and adds a user x509 cert if required.
func newClient() (*http.Client, error) {
	// If not using TLS, nothing to do.
	if !viper.IsSet("tls.user-cert") && !viper.IsSet("tls.user-key") {
		return &http.Client{}, nil
	}

	// If one is set but the other is not, notify the user as this is probably an error
	if viper.IsSet("tls.user-cert") && !viper.IsSet("tls.user-key") {
		color.Red("Warning: tls.user-key is not set. Mutual TLS will not be used.")
		return &http.Client{}, nil
	}
	if viper.IsSet("tls.user-key") && !viper.IsSet("tls.user-cert") {
		color.Red("Warning: tls.user-cert is not set. Mutual TLS will not be used.")
		return &http.Client{}, nil
	}

	keyBlock, err := ioutil.ReadFile(viper.GetString("tls.user-key"))
	if err != nil {
		return nil, err
	}

	certBlock, err := ioutil.ReadFile(viper.GetString("tls.user-cert"))
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certBlock, keyBlock)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	return client, nil
}
