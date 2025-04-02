package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	//"net/http/httputil"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var ()

const ()

type CNF struct {
	TBH string `json:"tbh,omitempty"`
}

type CustomClaimsExample struct {
	*jwt.RegisteredClaims
	Scope string `json:"scope"`
	CNF   `json:"cnf"`
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ekm, err := r.TLS.ExportKeyingMaterial("EXPORTER-my_label", []byte("mycontext"), 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Printf("EKM  from TLS: %s\n", hex.EncodeToString(ekm))

		ha := sha256.New()
		ha.Write(ekm)
		bsr := ha.Sum(nil)

		encodedEKM := base64.RawURLEncoding.EncodeToString(bsr)
		fmt.Printf("Encoded EKM  from TLS: %s\n", encodedEKM)

		// try to extract the authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fields := strings.Fields(authHeader)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Bearer") {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tokenString := fields[1]

		// Verify the JWT, first read the cert (yes, this is at request time but you can verify this in any way you want)

		cl := &CustomClaimsExample{}
		token, _, err := new(jwt.Parser).ParseUnverified(tokenString, cl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		keyID := token.Header["kid"]
		fmt.Printf("JWT KeyID %s\n", keyID)

		// this is the cert
		if keyID == "123456" {
			certBytes, err := os.ReadFile("../certs/clientjwt.crt")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			certBlock, _ := pem.Decode(certBytes)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			pcl := &CustomClaimsExample{}

			token, err := jwt.ParseWithClaims(tokenString, pcl, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return cert.PublicKey, nil
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if claims, ok := token.Claims.(*CustomClaimsExample); ok && token.Valid {

				fmt.Printf("EKM from Claim: %v\n", claims.CNF.TBH)

				h := sha256.New()
				h.Write(ekm)
				bs := h.Sum(nil)

				encodedEKM := base64.RawURLEncoding.EncodeToString(bs)

				if encodedEKM == claims.CNF.TBH {
					fmt.Println("EKM matches")
				} else {
					fmt.Println("EKM verification failed")
					http.Error(w, "EKM Verification Failed", http.StatusInternalServerError)
					return
				}

			} else {
				http.Error(w, "Error parsing claims", http.StatusInternalServerError)
				return
			}

		} else {
			http.Error(w, "KeyID Not found", http.StatusInternalServerError)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
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
	err = server.ListenAndServeTLS("../certs/server.crt", "../certs/server.key")
	fmt.Printf("Unable to start Server %v", err)

}
