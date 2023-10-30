package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"

	//"net/http/httputil"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var ()

const ()

type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	ekm []byte
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ekm, err := r.TLS.ExportKeyingMaterial("my_nonce", nil, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Printf("EKM my_nonce from TLS: %s\n", hex.EncodeToString(ekm))
		event := &event{
			ekm: ekm,
		}
		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("event")).(event)
	e := r.Header.Get("ekm")
	if e == "" {
		http.Error(w, "Error: no ekm provided in header", http.StatusInternalServerError)
		return
	}
	fmt.Printf("EKM value from header %s\n", e)
	if e != hex.EncodeToString(val.ekm) {
		http.Error(w, "Error: ekm tls value does not match header", http.StatusInternalServerError)
		return
	}
	fmt.Println("EKM value matches header")
	fmt.Fprint(w, "ok")
}

func main() {

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/get").HandlerFunc(gethandler)

	var err error
	tlsConfig := &tls.Config{}

	server := &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("certs/server.crt", "certs/server.key")
	fmt.Printf("Unable to start Server %v", err)

}
