package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"time"
)

func loggedCloser(c io.Closer) {
	if err := c.Close(); err != nil {
		log.Fatal(err)
	}
}

func getPemFromApi(domain string) (error, []string) {
	//goland:noinspection SpellCheckingInspection
	type CertificateInChain struct {
		CertificatePem string `json:"certificate_pem"`
		Pem            struct {
			Hashes struct {
				Sha265 string `json:"sha256"`
			} `json:"hashes"`
		} `json:"pem"`
	}

	// only parse as little as possible
	type CertistReply struct {
		Certificate struct {
			Pem string `json:"pem"`
		} `json:"certificate"`
		CertificatesInTheChain []CertificateInChain `json:"chain"`
	}

	var myClient = &http.Client{Timeout: 15 * time.Second}
	r, err := myClient.Get(fmt.Sprintf("https://api.cert.ist/%s", domain))
	if err != nil {
		return err, []string{}
	}
	defer loggedCloser(r.Body)

	bod, _ := ioutil.ReadAll(r.Body)
	api := new(CertistReply)

	err = json.Unmarshal(bod, &api)
	if err != nil {
		return err, []string{}
	}

	all := make([]string, len(api.CertificatesInTheChain))
	for c, cert := range api.CertificatesInTheChain {
		all[c] = cert.Pem.Hashes.Sha265
	}
	return nil, all
}

func getPemFromLocal(address string) (error, []string) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err, []string{}
	}
	defer loggedCloser(conn)
	all := make([]string, len(conn.ConnectionState().PeerCertificates))
	for count, cert := range conn.ConnectionState().PeerCertificates {
		var b bytes.Buffer
		err := pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return err, []string{}
		}
		sum256 := sha256.Sum256([]byte(b.String()))
		all[count] = fmt.Sprintf("%x", sum256)
	}
	return nil, all
}

func validateCertificate(domain string) bool {
	e, hashesFromLocal := getPemFromLocal(fmt.Sprintf("%s:443", domain))
	if e != nil {
		panic(e)
	}
	e, hashesFromApi := getPemFromApi(domain)
	if e != nil {
		panic(e)
	}

	areEqual := reflect.DeepEqual(hashesFromLocal, hashesFromApi)
	log.Printf("Domain: %s, Certificates matched? %t", domain, areEqual)
	return areEqual
}

func main() {
	validateCertificate("urip.io")
	validateCertificate("cert.ist")
	validateCertificate("tilltrump.com")
	validateCertificate("asciirange.com")
}
