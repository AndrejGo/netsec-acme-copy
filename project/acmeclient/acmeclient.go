package acmeclient

import (
	"acme/httpserver"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

// MetaObject holds a JSON struct in the directory response
type MetaObject struct {
	ExternalAccountRequired bool
	TermsOfService          string
}

// Directory holds the directory JSON returned by the ACME server
type Directory struct {
	NewNonce   string
	NewAccount string
	NewOrder   string
	Meta       MetaObject
	RevokeCert string
	KeyChange  string
}

// AcmeClient is a structure that holds all information about the ACME client
// like the server url, paths, ...
type AcmeClient struct {
	accountURL       string
	dir              Directory
	nonce            string
	privateKey       *ecdsa.PrivateKey
	Authorizations   []string
	Identifiers      []Identifier
	finalize         string
	challengeType    string
	dnsTxtDomain     *string
	dnsTxtValue      *string
	ip               string
	authIndex        int
	generatedPrivKey crypto.PrivateKey
	certDlLink       string
	httpAuth         *string
	trustingClient   *http.Client
}

// JSONWebKey object
type JSONWebKey struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// NewAccountHeader object
type NewAccountHeader struct {
	Alg   string     `json:"alg"`
	Jwk   JSONWebKey `json:"jwk"`
	Nonce string     `json:"nonce"`
	URL   string     `json:"url"`
}

// StandardHeader object
type StandardHeader struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
}

// NewAccountPayload object
type NewAccountPayload struct {
	Terms bool `json:"termsOfServiceAgreed"`
}

// JWSMessage object
type JWSMessage struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// ClientInitStruct ...
type ClientInitStruct struct {
	ChalType     string
	Directory    string
	DNSTxtDomain *string
	DNSTxtValue  *string
	IP           string
	HTTPAuth     *string
}

// NewAcmeClient create a new AcmeClient with a given ACME server
func NewAcmeClient(is ClientInitStruct) (AcmeClient, error) {

	// Trust pebble.minica
	pmp, err := ioutil.ReadFile("pebble.minica.pem")
	if err != nil {
		panic(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(pmp)

	// Trust pebble.minica
	pmp, err = ioutil.ReadFile("certSchenanigans/cacert.pem")
	if err != nil {
		panic(err)
	}
	certPool.AppendCertsFromPEM(pmp)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}

	trustingClient := &http.Client{
		Transport: transport,
	}

	// Get the server's directory. If this fails, the server probably
	// doesn't work
	resp, err := trustingClient.Get(is.Directory)
	if err != nil {
		return AcmeClient{}, err
	}

	defer resp.Body.Close()

	// Get the directory from the response
	dir := Directory{}
	err = json.NewDecoder(resp.Body).Decode(&dir)
	if err != nil {
		return AcmeClient{}, err
	}

	// Generate an ES256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return AcmeClient{}, err
	}

	ct := "dns-01"
	if is.ChalType == "http01" {
		ct = "http-01"
	}

	client := AcmeClient{
		dir:            dir,
		privateKey:     privateKey,
		challengeType:  ct,
		dnsTxtDomain:   is.DNSTxtDomain,
		dnsTxtValue:    is.DNSTxtValue,
		ip:             is.IP,
		authIndex:      0,
		httpAuth:       is.HTTPAuth,
		trustingClient: trustingClient,
	}

	log.Printf("Created ACME client with directory")

	return client, nil
}

// GetNonce gets the nonce from the ACME server
func (c *AcmeClient) GetNonce() (string, error) {
	resp, err := c.trustingClient.Head(c.dir.NewNonce)
	if err != nil {
		return "", err
	}

	c.nonce = resp.Header.Get("Replay-Nonce")
	return c.nonce, nil
}

// JSONWebKey prepares the jwk field of the "protected" field
func (c *AcmeClient) JSONWebKey() (JSONWebKey, error) {
	bX := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(c.privateKey.PublicKey.X.Bytes())
	bY := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(c.privateKey.PublicKey.Y.Bytes())

	keyObj := JSONWebKey{
		Kty: "EC",
		Crv: "P-256",
		X:   bX,
		Y:   bY,
	}

	return keyObj, nil
}

// PrepareHeaderWithURL ...
func (c *AcmeClient) PrepareHeaderWithURL(url string) (string, error) {

	if c.nonce == "" {
		return "", fmt.Errorf("Should have had nonce by now")
	}

	header := StandardHeader{
		Alg:   "ES256",
		Kid:   c.accountURL,
		Nonce: c.nonce,
		URL:   url,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(headerBytes), nil
}

// PrepareNewAccountHeader prepares the "protected" field of a new account request
func (c *AcmeClient) PrepareNewAccountHeader() (string, error) {

	jwk, err := c.JSONWebKey()
	if err != nil {
		return "", err
	}

	if c.nonce == "" {
		c.GetNonce()
	}

	header := NewAccountHeader{
		Alg:   "ES256",
		Jwk:   jwk,
		Nonce: c.nonce,
		URL:   c.dir.NewAccount,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(headerBytes), nil
}

// PrepareNewAccountPayload prepares the "payload" field of a new account request
func (c *AcmeClient) PrepareNewAccountPayload() (string, error) {

	payload := NewAccountPayload{Terms: true}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(payloadBytes), nil
}

// CreateSignature concatenates the NewAccount header and payload, hashes them and applies
// an ECDSA signature
func (c *AcmeClient) CreateSignature(header, payload string) (*big.Int, *big.Int, error) {

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(header + "." + payload))
	hash := hasher.Sum(nil)

	return ecdsa.Sign(rand.Reader, c.privateKey, hash)
}

// EncodeSignature transforms r and s into a base64 encoded representation
func (c *AcmeClient) EncodeSignature(r, s *big.Int) string {

	bytesR := r.Bytes()
	bytesS := s.Bytes()

	paddingBytesR := []byte{}
	paddingBytesS := []byte{}

	for i := 0; i < 32-len(bytesR); i++ {
		paddingBytesR = append(paddingBytesR, 0)
	}
	for i := 0; i < 32-len(bytesS); i++ {
		paddingBytesS = append(paddingBytesS, 0)
	}

	paddedR := append(paddingBytesR, r.Bytes()...)
	paddedS := append(paddingBytesS, s.Bytes()...)
	rsBytes := append(paddedR, paddedS...)

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(rsBytes)
}

// PrepareNewAccountRequest ...
func (c *AcmeClient) PrepareNewAccountRequest() (JWSMessage, error) {
	header, err := c.PrepareNewAccountHeader()
	if err != nil {
		return JWSMessage{}, err
	}
	payload, err := c.PrepareNewAccountPayload()
	if err != nil {
		return JWSMessage{}, err
	}
	r, s, err := c.CreateSignature(header, payload)
	if err != nil {
		return JWSMessage{}, err
	}
	signature := c.EncodeSignature(r, s)

	return JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	}, nil
}

// CreateNewAccount ...
func (c *AcmeClient) CreateNewAccount() error {
	newAccountRequest, err := c.PrepareNewAccountRequest()
	if err != nil {
		return err
	}

	reqBody, err := json.Marshal(newAccountRequest)
	if err != nil {
		return err
	}

	resp, err := c.trustingClient.Post(c.dir.NewAccount, "application/jose+json", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyString, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 201 {
		str := fmt.Sprintf("Account creation was not successfull\n%s\n", bodyString)
		return fmt.Errorf(str)
	}

	c.accountURL = resp.Header.Get("Location")
	c.nonce = resp.Header.Get("Replay-Nonce")

	log.Printf("Created new account with the ACME server\n")

	return nil
}

// =================================================================== //
// Certificate Order Functions
// =================================================================== //

// Identifier represents a type-id pair of each identity that the
// ACME client wants a certificate for
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// SigningOrder represents the json structure that will initially request
// the certificates from the ACME server
type SigningOrder struct {
	Status      string       `json:"status"`
	Identifiers []Identifier `json:"identifiers"`
}

// PrepareOrderPayload creates a base64 encoded payload for the certificate order
// message
func (c *AcmeClient) PrepareOrderPayload(identifiers []string) (string, error) {

	var ids []Identifier
	for _, identifier := range identifiers {
		ids = append(ids, Identifier{"dns", identifier})
	}

	so := SigningOrder{
		Status:      "pending",
		Identifiers: ids,
	}

	soBytes, err := json.Marshal(so)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(soBytes), nil
}

// PrepareCertificateOrderHeader prepares the "protected" field of a new account request
func (c *AcmeClient) PrepareCertificateOrderHeader() (string, error) {

	if c.nonce == "" {
		return "", fmt.Errorf("Should have had nonce by now")
	}

	header := StandardHeader{
		Alg:   "ES256",
		Kid:   c.accountURL,
		Nonce: c.nonce,
		URL:   c.dir.NewOrder,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(headerBytes), nil
}

// PrepareCertificateOrder ...
func (c *AcmeClient) PrepareCertificateOrder(identifiers []string) (JWSMessage, error) {

	header, err := c.PrepareCertificateOrderHeader()
	if err != nil {
		return JWSMessage{}, err
	}

	payload, err := c.PrepareOrderPayload(identifiers)
	if err != nil {
		return JWSMessage{}, err
	}

	r, s, err := c.CreateSignature(header, payload)
	if err != nil {
		return JWSMessage{}, err
	}

	signature := c.EncodeSignature(r, s)

	return JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	}, nil
}

// OrderResponse ...
type OrderResponse struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	Finalize       string       `json:"finalize"`
	Authorizations []string     `json:"authorizations"`
}

// OrderCertificates ...
func (c *AcmeClient) OrderCertificates(identifiers []string) error {
	order, err := c.PrepareCertificateOrder(identifiers)
	if err != nil {
		return err
	}

	reqBody, err := json.Marshal(order)
	if err != nil {
		return err
	}

	resp, err := c.trustingClient.Post(c.dir.NewOrder, "application/jose+json", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyString, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 201 {
		str := fmt.Sprintf("Order was not successfull\n%s\n", bodyString)
		return fmt.Errorf(str)
	}

	var data OrderResponse
	err = json.Unmarshal([]byte(bodyString), &data)
	if err != nil {
		return err
	}

	// domains are not sorted
	c.Authorizations = data.Authorizations
	c.Identifiers = data.Identifiers
	c.finalize = data.Finalize
	c.nonce = resp.Header.Get("Replay-Nonce")

	log.Printf("Ordered certificate for domains %+v\n", c.Identifiers)

	return nil
}

// GetNextAuthorization ...
func (c *AcmeClient) GetNextAuthorization() (string, string) {
	if c.authIndex == len(c.Authorizations) {
		return "", ""
	}

	auth := c.Authorizations[c.authIndex]

	iden := c.Identifiers[c.authIndex].Value

	c.authIndex++

	return auth, iden
}

// Challenge ...
type Challenge struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

// AuthorizationResponse ...
type AuthorizationResponse struct {
	Status      string       `json:"status"`
	Expires     string       `json:"expires"`
	Identifiers []Identifier `json:"identifiers"`
	Challenges  []Challenge  `json:"challenges"`
}

// DoneAuthorizing ...
func (c *AcmeClient) DoneAuthorizing() bool {
	return c.authIndex == len(c.Authorizations)
}

func (c *AcmeClient) getChallenge() (Challenge, string, string, error) {
	// Get the next authorization path
	path, domain := c.GetNextAuthorization()
	if path == "" {
		return Challenge{}, "", "", nil
	}

	// Do a POST-as-GET to the path
	header, err := c.PrepareHeaderWithURL(path)
	if err != nil {
		return Challenge{}, "", "", err
	}
	payload := ""
	r, s, err := c.CreateSignature(header, payload)
	if err != nil {
		return Challenge{}, "", "", err
	}
	signature := c.EncodeSignature(r, s)
	postAsGet := JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	}

	reqBody, err := json.Marshal(postAsGet)
	if err != nil {
		return Challenge{}, "", "", err
	}

	resp, err := c.trustingClient.Post(path, "application/jose+json", bytes.NewBuffer(reqBody))
	if err != nil {
		return Challenge{}, "", "", err
	}
	defer resp.Body.Close()

	bodyString, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Challenge{}, "", "", err
	}

	if resp.StatusCode != 200 {
		str := fmt.Sprintf("Authorization was not successfull\n%s\n", bodyString)
		return Challenge{}, "", "", fmt.Errorf(str)
	}

	var data AuthorizationResponse
	err = json.Unmarshal([]byte(bodyString), &data)
	if err != nil {
		return Challenge{}, "", "", err
	}

	ch := Challenge{}
	for _, chal := range data.Challenges {
		if chal.Type == c.challengeType {
			ch = chal
			break
		}
	}

	c.nonce = resp.Header.Get("Replay-Nonce")

	return ch, domain, path, nil
}

func (c *AcmeClient) constructKeyAuthorization(token string) (string, error) {

	jwk, err := c.JSONWebKey()
	if err != nil {
		return "", err
	}

	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}

	hasher := crypto.SHA256.New()
	hasher.Write(jwkBytes)
	hash := hasher.Sum(nil)

	hashEncoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash)

	return token + "." + hashEncoded, nil
}

func (c *AcmeClient) prepareServerNotification(path string) (JWSMessage, error) {
	header, err := c.PrepareHeaderWithURL(path)
	if err != nil {
		return JWSMessage{}, err
	}

	payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("{}"))

	r, s, err := c.CreateSignature(header, payload)
	if err != nil {
		return JWSMessage{}, err
	}

	signature := c.EncodeSignature(r, s)

	return JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	}, nil
}

func (c *AcmeClient) notifyServer(path string) error {

	log.Printf("Notifying the ACME server")

	notification, err := c.prepareServerNotification(path)
	if err != nil {
		return err
	}

	reqBody, err := json.Marshal(notification)
	if err != nil {
		return err
	}

	resp, err := c.trustingClient.Post(path, "application/jose+json", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Notifying the server was not successfull")
	}

	c.nonce = resp.Header.Get("Replay-Nonce")

	return nil
}

func (c *AcmeClient) checkAuthorizationStatus(path string) (string, error) {

	log.Printf("Checking authorization")

	// Do a POST-as-GET to the path
	header, err := c.PrepareHeaderWithURL(path)
	if err != nil {
		return "", err
	}
	payload := ""
	r, s, err := c.CreateSignature(header, payload)
	if err != nil {
		return "", err
	}
	signature := c.EncodeSignature(r, s)
	postAsGet := JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	}

	reqBody, err := json.Marshal(postAsGet)
	if err != nil {
		return "", err
	}

	resp, err := c.trustingClient.Post(path, "application/jose+json", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyString, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		str := fmt.Sprintf("Authorization check was not successfull\n%s\n", bodyString)
		return "", fmt.Errorf(str)
	}

	var data AuthorizationResponse
	err = json.Unmarshal([]byte(bodyString), &data)
	if err != nil {
		return "", err
	}

	c.nonce = resp.Header.Get("Replay-Nonce")

	return data.Status, nil
}

// ResolveAuthorization ...
func (c *AcmeClient) ResolveAuthorization() error {

	// Get the next challenge to be fulfilled
	chal, domain, authPath, err := c.getChallenge()
	if err != nil {
		return err
	}

	log.Printf("Starting %s resolution of challenge for %s\n", c.challengeType, domain)

	empty := Challenge{}
	if chal == empty {
		return nil
	}

	// Calculate the key authorization
	keyAuthorization, err := c.constructKeyAuthorization(chal.Token)
	if err != nil {
		return err
	}

	if chal.Type == "dns-01" {
		// Hash and base64 the authorization
		hasher := crypto.SHA256.New()
		hasher.Write([]byte(keyAuthorization))
		hash := hasher.Sum(nil)
		hashEncoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash)

		// Pass the values to the DNS server
		log.Printf("Passing values to the DNS server")
		*(c.dnsTxtDomain) = "_acme-challenge." + domain + "."
		*(c.dnsTxtValue) = hashEncoded

	} else if chal.Type == "http-01" {
		// Register the token and auth with the HTTP server
		httpserver.Register(chal.Token, keyAuthorization)
	}

	time.Sleep(time.Second * 2)

	// Notify ACME server
	c.notifyServer(chal.URL)

	for {
		// Check the authorization
		status, err := c.checkAuthorizationStatus(authPath)
		if err != nil {
			return err
		}
		switch status {
		case "invalid":
			return fmt.Errorf("Authorization invalid")
		case "valid":
			return nil
		default:
			time.Sleep(time.Millisecond * 100)
		}
	}

	return nil
}

// =================================================================== //
// CSR Functions
// =================================================================== //

func (c *AcmeClient) prepareCSR() (string, error) {
	dnsNames := []string{}
	for _, i := range c.Identifiers {
		dnsNames = append(dnsNames, i.Value)
	}

	subject := pkix.Name{
		CommonName:         dnsNames[0],
		Country:            []string{"CH"},
		Province:           []string{"Zuerich"},
		Locality:           []string{"Zuerich"},
		Organization:       []string{"org llc"},
		OrganizationalUnit: []string{"IT"},
	}

	template := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            subject,
		DNSNames:           dnsNames,
	}

	// Generate an RSA 2048 key pair
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	derCSR, err := x509.CreateCertificateRequest(
		rand.Reader,
		&template,
		privkey,
	)
	if err != nil {
		return "", err
	}

	c.generatedPrivKey = privkey

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(derCSR), nil
}

// CSR ...
type CSR struct {
	Csr string `json:"csr"`
}

// CsrResponse ...
type CsrResponse struct {
	Status      string `json:"status"`
	Certificate string `json:"certificate"`
}

// SendCSR ...
func (c *AcmeClient) SendCSR() error {

	log.Printf("Sedning CSR")

	header, err := c.PrepareHeaderWithURL(c.finalize)
	if err != nil {
		return err
	}

	csrString, err := c.prepareCSR()
	if err != nil {
		return err
	}

	csrObj := CSR{
		Csr: csrString,
	}
	csrBytes, err := json.Marshal(csrObj)
	if err != nil {
		return err
	}
	body := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(csrBytes)

	r, s, err := c.CreateSignature(header, body)
	if err != nil {
		return err
	}

	signature := c.EncodeSignature(r, s)

	message := JWSMessage{
		Protected: header,
		Payload:   body,
		Signature: signature,
	}

	reqBody, err := json.Marshal(message)
	if err != nil {
		return err
	}

	resp, err := c.trustingClient.Post(c.finalize, "application/jose+json", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("CSR was not successfull")
	}

	bodyString, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	csrResp := CsrResponse{}
	err = json.Unmarshal([]byte(bodyString), &csrResp)
	if err != nil {
		return err
	}

	for {
		c.nonce = resp.Header.Get("Replay-Nonce")
		// Wait if necessary
		if csrResp.Status == "processing" {
			retryAfter := resp.Header.Get("Retry-After")
			t, err := strconv.Atoi(retryAfter)
			if err != nil {
				t = 500
			}
			log.Printf("Waiting for %d miliseconds", t)
			time.Sleep(time.Millisecond * time.Duration(t))
		}
		if csrResp.Status == "valid" {
			c.certDlLink = csrResp.Certificate
			log.Printf("CSR validated")
			break
		}

		// Send post-as-get
		resource := resp.Header.Get("Location")

		header, err := c.PrepareHeaderWithURL(resource)
		if err != nil {
			return err
		}
		payload := ""
		r, s, err := c.CreateSignature(header, payload)
		if err != nil {
			return err
		}
		signature := c.EncodeSignature(r, s)
		postAsGet := JWSMessage{
			Protected: header,
			Payload:   payload,
			Signature: signature,
		}

		reqBody, err := json.Marshal(postAsGet)
		if err != nil {
			return err
		}

		resp, err = c.trustingClient.Post(resource, "application/jose+json", bytes.NewBuffer(reqBody))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return fmt.Errorf("CSR was not successfull")
		}

		bodyString, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		err = json.Unmarshal([]byte(bodyString), &csrResp)
		if err != nil {
			return err
		}
	}

	return nil
}

// DownloadCert ...
func (c *AcmeClient) DownloadCert() error {

	log.Printf("Downloading certificate")

	header, err := c.PrepareHeaderWithURL(c.certDlLink)
	if err != nil {
		return err
	}
	payload := ""
	r, s, err := c.CreateSignature(header, payload)
	if err != nil {
		return err
	}
	signature := c.EncodeSignature(r, s)
	postAsGet := JWSMessage{
		Protected: header,
		Payload:   payload,
		Signature: signature,
	}

	reqBody, err := json.Marshal(postAsGet)
	if err != nil {
		return err
	}

	resp, err := c.trustingClient.Post(c.certDlLink, "application/jose+json", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Failed to download certificate")
	}

	bodyString, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("server.cert", []byte(bodyString), 0644)
	if err != nil {
		return err
	}

	pemkey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(c.generatedPrivKey.(*rsa.PrivateKey)),
		},
	)

	err = ioutil.WriteFile("server.key", []byte(pemkey), 0644)
	if err != nil {
		return err
	}

	c.nonce = resp.Header.Get("Replay-Nonce")

	return nil
}

// =================================================================== //
// Certificate Revocation
// =================================================================== //

// Revocation ...
type Revocation struct {
	Certificate string `json:"certificate"`
	Reason      int    `json:"reason"`
}

func (c *AcmeClient) prepareRevocation() (JWSMessage, error) {

	header, err := c.PrepareHeaderWithURL(c.dir.RevokeCert)
	if err != nil {
		return JWSMessage{}, err
	}

	certBytes, err := ioutil.ReadFile("server.cert")
	if err != nil {
		return JWSMessage{}, err
	}

	block, _ := pem.Decode(certBytes)

	revocation := Revocation{
		Certificate: base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(block.Bytes),
	}
	revBytes, err := json.Marshal(revocation)
	if err != nil {
		return JWSMessage{}, err
	}

	revEncoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(revBytes)

	r, s, err := c.CreateSignature(header, revEncoded)
	if err != nil {
		return JWSMessage{}, err
	}
	signature := c.EncodeSignature(r, s)
	revokeMessage := JWSMessage{
		Protected: header,
		Payload:   revEncoded,
		Signature: signature,
	}

	return revokeMessage, nil
}

// Revoke ...
func (c *AcmeClient) Revoke() error {

	log.Printf("Revoking certificate")

	revocation, err := c.prepareRevocation()

	reqBody, err := json.Marshal(revocation)
	if err != nil {
		return err
	}

	resp, err := c.trustingClient.Post(c.dir.RevokeCert, "application/jose+json", bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Revocation was not successfull")
	}

	c.nonce = resp.Header.Get("Replay-Nonce")

	return nil
}
