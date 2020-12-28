package httpserver

import (
	"log"
	"net/http"
)

// Start ...
func Start() {
	go func() {
		err := http.ListenAndServe(":5002", nil)
		if err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
}

// Register ...
func Register(token, authorization string) {
	http.HandleFunc(
		"/.well-known/acme-challenge/"+token,
		func(res http.ResponseWriter, req *http.Request) {
			res.Write([]byte(authorization))
			res.Header().Set("Content-Type", "application/octet-stream")
			log.Printf("HTTP server responded with auth")
		})
}
