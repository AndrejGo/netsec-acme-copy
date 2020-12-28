package httpsserver

import (
	"log"
	"net/http"
)

func handleHome(res http.ResponseWriter, req *http.Request) {
	log.Printf("HTTPS server was accessed")
}

// Start starts an https server
func Start() {
	http.HandleFunc("/", handleHome)

	go func() {
		err := http.ListenAndServeTLS(":5001", "server.cert", "server.key", nil)
		if err != nil {
			log.Fatal(err)
		}
	}()
}
