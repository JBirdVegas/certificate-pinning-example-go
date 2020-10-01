package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func loggedCloser(c io.Closer) {
	if err := c.Close(); err != nil {
		log.Fatal(err)
	}
}

func getPemFromApi(domain string) (error, string) {
	//goland:noinspection SpellCheckingInspection
	type CertistReply struct {
		Certificate struct {
			Pem string `json:"pem"`
		} `json:"certificate"`
	}

	var myClient = &http.Client{Timeout: 15 * time.Second}
	r, err := myClient.Get(fmt.Sprintf("https://api.cert.ist/%s", domain))
	if err != nil {
		return err, ""
	}
	defer loggedCloser(r.Body)

	bod, _ := ioutil.ReadAll(r.Body)
	api := new(CertistReply)

	err = json.Unmarshal(bod, &api)
	if err != nil {
		return err, ""
	}
	return nil, api.Certificate.Pem
}

func getPemFromLocal(address string) (error, string) {
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err, ""
	}
	defer loggedCloser(conn)
	var b bytes.Buffer
	for _, cert := range conn.ConnectionState().PeerCertificates {
		err := pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return err, ""
		}
		break
	}
	return nil, b.String()
}

func validateCertificate(domain string) bool {
	e, pemFoundLocally := getPemFromLocal(fmt.Sprintf("%s:443", domain))
	if e != nil {
		panic(e)
	}
	e, pemFoundFromApi := getPemFromApi(domain)
	if e != nil {
		panic(e)
	}

	areEqual := pemFoundLocally == pemFoundFromApi
	log.Printf("Domain: %s, Certificates matched? %t", domain, areEqual)
	return areEqual
}

func main() {
	validateCertificate("urip.io")
	validateCertificate("cert.ist")
	validateCertificate("tilltrump.com")
	validateCertificate("asciirange.com")
}
