package main

import (
	"acme/acmeclient"
	"acme/dnsserver"
	"acme/httpserver"
	"acme/httpsserver"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type domainList []string

func (d *domainList) Set(value string) error {
	*d = append(*d, value)
	return nil
}

func (d *domainList) String() string {
	return fmt.Sprintf("%s", *d)
}

func main() {

	// ================================================================ //
	// HANDLE COMMAND LINE ARGUMENTS
	// ================================================================ //

	// Required 'type' parameter
	chalType := os.Args[1]

	cmdLine := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	// directory
	directory := cmdLine.String("dir", "https://localhost:14000/dir", "Directory resource of the ACME server")
	// record
	record := cmdLine.String("record", "1.2.3.4", "An IP address that will be returned for every DNS lookup")
	// one or more domains
	var domains domainList
	cmdLine.Var(&domains, "domain", "Domain name for which we are obtaining a certificate")
	// optional revoke
	revoke := cmdLine.Bool("revoke", false, "Should the cert be revoked after setting up the HTTPS server")

	cmdLine.Parse(os.Args[2:])

	// ================================================================ //
	// LAUNCH THE DNS SERVER
	// ================================================================ //
	dnsTxtDomain := ""
	dnsTxtValue := ""
	log.Printf("Launching DNS server")
	go dnsserver.StartDNS(*record, &dnsTxtDomain, &dnsTxtValue)

	// ================================================================ //
	// LAUNCH THE HTTP SERVER
	// ================================================================ //
	log.Printf("Launching HTTP server")
	httpserver.Start()

	// ================================================================ //
	// ACME CLIENT
	// ================================================================ //

	is := acmeclient.ClientInitStruct{
		ChalType:     chalType,
		Directory:    *directory,
		DNSTxtDomain: &dnsTxtDomain,
		DNSTxtValue:  &dnsTxtValue,
		IP:           *record,
	}
	client, err := acmeclient.NewAcmeClient(is)
	if err != nil {
		log.Fatalf("Error creating ACME client: %s", err.Error())
	}

	err = client.CreateNewAccount()
	if err != nil {
		log.Fatalf("Error creating client account: %s", err.Error())
	}

	err = client.OrderCertificates(domains)
	if err != nil {
		log.Fatalf("Error creating certificate order: %s", err.Error())
	}

	// Do all of the authorizations
	for {
		if client.DoneAuthorizing() {
			break
		}
		err := client.ResolveAuthorization()
		if err != nil {
			log.Fatalf("Error authorizing: %s", err.Error())
		}
		log.Printf("Authorization OK")
	}

	// Send CSR
	err = client.SendCSR()
	if err != nil {
		panic(err)
	}

	time.Sleep(time.Second)

	// Download the Certificate and save it to
	// server.cert, save the private key to server.key
	err = client.DownloadCert()
	if err != nil {
		panic(err)
	}

	// ================================================================ //
	// Revoke if necessary
	// ================================================================ //
	if *revoke {
		err := client.Revoke()
		if err != nil {
			panic(err)
		}
	}

	time.Sleep(time.Second)

	// ================================================================ //
	// HTTPS Server
	// ================================================================ //
	httpsserver.Start()
	log.Printf("Started the https server")

	// ================================================================ //
	// RUN THE SHUTDOWN SERVER
	// ================================================================ //

	shutdownChan := make(chan int)
	shutdown := func(res http.ResponseWriter, req *http.Request) {
		shutdownChan <- 1
	}

	http.HandleFunc("/shutdown", shutdown)

	go func() {
		err := http.ListenAndServe(":5003", nil)
		if err != nil {
			log.Fatal(err)
		}
	}()

	log.Printf("Started the shutdown server")

	for {
		x := <-shutdownChan
		if x == 1 {
			break
		}
	}

	err = os.Remove("server.cert")
	if err != nil {
		panic(err)
	}

	err = os.Remove("server.key")
	if err != nil {
		panic(err)
	}

	log.Printf("Shutting down")
}
