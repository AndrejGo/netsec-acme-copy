package acmeclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func assertErrorNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(fmt.Sprintf("error not nil: %s", err.Error()))
	}
}

func prepareDirectory(host, protocol string) Directory {
	return Directory{
		KeyChange: protocol + host + "/rollover-account-key",
		Meta: MetaObject{
			ExternalAccountRequired: false,
			TermsOfService:          "data:text/plain,Do%20what%20thou%20wilt",
		},
		NewAccount: protocol + host + "/sign-me-up",
		NewNonce:   protocol + host + "/nonce-plz",
		NewOrder:   protocol + host + "/order-plz",
		RevokeCert: protocol + host + "/revoke-cert",
	}
}

func direcoryMock(w http.ResponseWriter, r *http.Request) {
	protocol := "http://"
	if r.TLS != nil {
		protocol = "https://"
	}
	dirJSON, err := json.Marshal(prepareDirectory(r.Host, protocol))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(dirJSON)
}

func nonceMock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=0, no-cache")
	w.Header().Set("Link", "<https://192.168.56.10:14000/dir>;rel=\"index\"")
	w.Header().Set("Replay-Nonce", "uVvYOwTYQnEI1wVA6uFAJg")
	w.Header().Set("Date", "Sat, 24 Oct 2020 17:25:01 GMT")
}

func acmeServerMock() *httptest.Server {
	handler := http.NewServeMux()

	handler.HandleFunc("/dir", direcoryMock)
	handler.HandleFunc("/nonce-plz", nonceMock)

	srv := httptest.NewUnstartedServer(handler)

	listener, err := net.Listen("tcp", "127.0.0.1:62600")
	if err != nil {
		_ = fmt.Errorf("Warning, could not create listener")
		srv.Start()
		return srv
	}

	srv.Listener.Close()
	srv.Listener = listener

	srv.Start()

	return srv
}

// =================================================================== //
// Account Creation Functions
// =================================================================== //

func TestGetDirectory(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)

	assertErrorNil(t, err)

	gotNewNonce := client.dir.NewNonce
	gotNewAccount := client.dir.NewAccount
	gotNewOrder := client.dir.NewOrder
	gotMeta := client.dir.Meta
	gotRevokeCert := client.dir.RevokeCert
	gotKeyChange := client.dir.KeyChange

	dir := prepareDirectory(acmeSrv.URL, "")
	wantNewNonce := dir.NewNonce
	wantNewAccount := dir.NewAccount
	wantNewOrder := dir.NewOrder
	wantMeta := dir.Meta
	wantrevokeCert := dir.RevokeCert
	wantkeyChange := dir.KeyChange

	if gotNewNonce != wantNewNonce {
		t.Errorf("Wrong nonce URL, got %q want %q", gotNewNonce, wantNewNonce)
	}
	if gotNewAccount != wantNewAccount {
		t.Errorf("Wrong nonce URL, got %q want %q", gotNewAccount, wantNewAccount)
	}
	if gotNewOrder != wantNewOrder {
		t.Errorf("Wrong nonce URL, got %q want %q", gotNewOrder, wantNewOrder)
	}
	if gotMeta != wantMeta {
		t.Errorf("Wrong nonce URL, got %v want %v", gotMeta, wantMeta)
	}
	if gotRevokeCert != wantrevokeCert {
		t.Errorf("Wrong nonce URL, got %q want %q", gotRevokeCert, wantrevokeCert)
	}
	if gotKeyChange != wantkeyChange {
		t.Errorf("Wrong nonce URL, got %q want %q", gotKeyChange, wantkeyChange)
	}
}

func TestGetNonce(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)
	assertErrorNil(t, err)

	nonce, err := client.GetNonce()
	assertErrorNil(t, err)

	want := "uVvYOwTYQnEI1wVA6uFAJg"

	if want != nonce {
		t.Errorf("Wrong nonce, got %q want %q", nonce, want)
	}
}

type JwsHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

func TestJsonWebKey(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)
	assertErrorNil(t, err)

	_, err = client.GetNonce()
	assertErrorNil(t, err)

	// Overwrite key with a repeatable value
	publicX, _ := new(big.Int).SetString("78829391758211464504697107895572924758192873546543788609700439785673817605839", 10)
	publicY, _ := new(big.Int).SetString("71664158334473486097120052068180212950206196593005762183753184087076566851724", 10)
	varD, _ := new(big.Int).SetString("13333636056072245290587644117468355132245901817019800344423480556177708517424", 10)
	client.privateKey = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     publicX,
			Y:     publicY,
		},
		D: varD,
	}

	jwk, err := client.JSONWebKey()
	assertErrorNil(t, err)

	want := JSONWebKey{
		Kty: "EC",
		Crv: "P-256",
		X:   "rkfax6Ui1xSB4LU47PGxcMSCpBHiCif_9PLwC_1ERs8",
		Y:   "nnB56MfZhYnOIoqONV-sfgXvJMdgOZqKW046wgoF4Iw",
	}

	if jwk.Crv != want.Crv || jwk.Kty != want.Kty || jwk.X != want.X || jwk.Y != want.Y {
		t.Errorf("Wrong jwk, got %+v want %+v", jwk, want)
	}
}

func TestPrepareNewAccountHeader(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)
	assertErrorNil(t, err)

	_, err = client.GetNonce()
	assertErrorNil(t, err)

	// Overwrite key with a repeatable value
	publicX, _ := new(big.Int).SetString("78829391758211464504697107895572924758192873546543788609700439785673817605839", 10)
	publicY, _ := new(big.Int).SetString("71664158334473486097120052068180212950206196593005762183753184087076566851724", 10)
	varD, _ := new(big.Int).SetString("13333636056072245290587644117468355132245901817019800344423480556177708517424", 10)
	client.privateKey = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     publicX,
			Y:     publicY,
		},
		D: varD,
	}

	header, err := client.PrepareNewAccountHeader()
	assertErrorNil(t, err)

	//{"alg":"ES256","jwk":"{"kty":"EC","crv":"P-256","x":"rkfax6Ui1xSB4LU47PGxcMSCpBHiCif_9PLwC_1ERs8","y":"nnB56MfZhYnOIoqONV-sfgXvJMdgOZqKW046wgoF4Iw"}","nonce":"uVvYOwTYQnEI1wVA6uFAJg","url":"http://127.0.0.1:62600/sign-me-up"}
	want := "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InJrZmF4NlVpMXhTQjRMVTQ3UEd4Y01TQ3BCSGlDaWZfOVBMd0NfMUVSczgiLCJ5Ijoibm5CNTZNZlpoWW5PSW9xT05WLXNmZ1h2Sk1kZ09acUtXMDQ2d2dvRjRJdyJ9LCJub25jZSI6InVWdllPd1RZUW5FSTF3VkE2dUZBSmciLCJ1cmwiOiJodHRwOi8vMTI3LjAuMC4xOjYyNjAwL3NpZ24tbWUtdXAifQ"

	if header != want {
		t.Errorf("Wrong new account header, got %q want %q", header, want)
	}
}

func TestPrepareNewAccountPayload(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)
	assertErrorNil(t, err)

	_, err = client.GetNonce()
	assertErrorNil(t, err)

	payload, err := client.PrepareNewAccountPayload()
	assertErrorNil(t, err)

	//{"termsOfServiceAgreed":true}
	want := "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZX0"

	if payload != want {
		t.Errorf("Wrong new account payload, got %q want %q", payload, want)
	}
}

func TestCreateSignature(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)
	assertErrorNil(t, err)

	// Overwrite key with a repeatable value
	publicX, _ := new(big.Int).SetString("78829391758211464504697107895572924758192873546543788609700439785673817605839", 10)
	publicY, _ := new(big.Int).SetString("71664158334473486097120052068180212950206196593005762183753184087076566851724", 10)
	varD, _ := new(big.Int).SetString("13333636056072245290587644117468355132245901817019800344423480556177708517424", 10)
	client.privateKey = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     publicX,
			Y:     publicY,
		},
		D: varD,
	}

	header, err := client.PrepareNewAccountHeader()
	assertErrorNil(t, err)

	payload, err := client.PrepareNewAccountPayload()
	assertErrorNil(t, err)

	r, s, err := client.CreateSignature(header, payload)
	assertErrorNil(t, err)

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(header + "." + payload))
	hash := hasher.Sum(nil)

	if !ecdsa.Verify(&client.privateKey.PublicKey, hash, r, s) {
		t.Errorf("New account signature did not verify\n")
	}
}

func TestEncodeSignature(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)
	assertErrorNil(t, err)

	r, _ := new(big.Int).SetString("5865ab0f6bc444f840617e8279ef25b247692f58a6ddc936a2be8416beee1327", 16)
	s, _ := new(big.Int).SetString("1506a7c30166231c15a7cdfb4ca83368192d431e4a227f19d6147ad6a78679e4", 16)

	want := "WGWrD2vERPhAYX6Cee8lskdpL1im3ck2or6EFr7uEycVBqfDAWYjHBWnzftMqDNoGS1DHkoifxnWFHrWp4Z55A"

	signature := client.EncodeSignature(r, s)

	if want != signature {
		t.Errorf("Wrong signature, got %q want %q", signature, want)
	}
}

// =================================================================== //
// Certificate Order Functions
// =================================================================== //
func TestPrepareOrderPayload(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)
	assertErrorNil(t, err)

	identifiers := []string{"*.example.com", "www.google.com"}

	order, err := client.PrepareOrderPayload(identifiers)
	assertErrorNil(t, err)

	//{"status":"pending","identifiers":[{"type":"dns","value":"*.example.com"},{"type":"dns","value":"www.google.com"}]}
	want := "eyJzdGF0dXMiOiJwZW5kaW5nIiwiaWRlbnRpZmllcnMiOlt7InR5cGUiOiJkbnMiLCJ2YWx1ZSI6IiouZXhhbXBsZS5jb20ifSx7InR5cGUiOiJkbnMiLCJ2YWx1ZSI6Ind3dy5nb29nbGUuY29tIn1dfQ"

	if want != order {
		t.Errorf("Wrong signing order, got %q want %q", order, want)
	}
}

func TestPrepareCertificateOrderHeader(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)
	assertErrorNil(t, err)

	_, err = client.GetNonce()
	assertErrorNil(t, err)

	// Overwrite key id with a repeatable value
	client.accountURL = "https://localhost:14000/account/4"

	header, err := client.PrepareCertificateOrderHeader()
	assertErrorNil(t, err)

	//{"alg":"ES256","kid":"https://localhost:14000/account/4","nonce":"uVvYOwTYQnEI1wVA6uFAJg","url":"http://127.0.0.1:62600/order-plz"}
	want := "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjE0MDAwL2FjY291bnQvNCIsIm5vbmNlIjoidVZ2WU93VFlRbkVJMXdWQTZ1RkFKZyIsInVybCI6Imh0dHA6Ly8xMjcuMC4wLjE6NjI2MDAvb3JkZXItcGx6In0"

	if header != want {
		t.Errorf("Wrong new account header, got %q want %q", header, want)
	}
}

func TestGetNextAuthorization(t *testing.T) {
	acmeSrv := acmeServerMock()
	defer acmeSrv.Close()

	domain := "example.com"
	txtRecord := "txt record"
	is := ClientInitStruct{
		ChalType:     "dns01",
		Directory:    acmeSrv.URL + "/dir",
		DNSTxtDomain: &domain,
		DNSTxtValue:  &txtRecord,
		IP:           "1.2.3.4",
	}
	client, err := NewAcmeClient(is)
	assertErrorNil(t, err)

	_, err = client.GetNonce()
	assertErrorNil(t, err)

	client.Authorizations = []string{"Auth-1", "Auth-2", "Auth-3"}

	path, domain := client.GetNextAuthorization()
	if path != "Auth-1" {
		t.Errorf("Wrong authorization, got %q want \"Auth-1\"", path)
	}

	path, domain = client.GetNextAuthorization()
	if path != "Auth-2" {
		t.Errorf("Wrong authorization, got %q want \"Auth-2\"", path)
	}

	path, domain = client.GetNextAuthorization()
	if path != "Auth-3" {
		t.Errorf("Wrong authorization, got %q want \"Auth-3\"", path)
	}

	path, domain = client.GetNextAuthorization()
	if path != "" {
		t.Errorf("Wrong authorization, got %q want \"\"", path)
	}
}
