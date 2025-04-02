package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

var (
	ekm []byte
)

type CNF struct {
	TBH string `json:"tbh,omitempty"`
}

type CustomClaimsExample struct {
	*jwt.RegisteredClaims
	Scope string `json:"scope"`
	CNF   `json:"cnf"`
}

func main() {

	caCert, err := os.ReadFile("../certs/root-ca.crt")
	if err != nil {
		fmt.Printf("Error reading cacert %v\n", err)
		return
	}

	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ServerName: "server.domain.com",
		RootCAs:    serverCertPool,
	}

	conn, err := tls.Dial("tcp", "localhost:8081", tlsConfig)
	if err != nil {
		fmt.Printf("Error dialing %v\n", err)
		return
	}
	cs := conn.ConnectionState()
	ekm, err = cs.ExportKeyingMaterial("EXPORTER-my_label", []byte("mycontext"), 32)
	if err != nil {
		fmt.Printf("Error getting ekm %v\n", err)
		return
	}
	fmt.Printf("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	client := http.Client{
		Transport: tr,
	}

	req, err := http.NewRequest(http.MethodGet, "https://localhost:8081/get", nil)
	if err != nil {
		fmt.Printf("Error creating request %v\n", err)
		return
	}
	// ************ do something here with the ekm value  ***************

	// what the following does is mints a JWT token which includes a claim denoting the
	//  EKM it is valid for.  The idea is the server will check this claim and authorize
	//  it only if the current TLS sessions EKM matches

	// now extract the signing private key
	keyBytes, err := os.ReadFile("../certs/clientjwt.key")
	if err != nil {
		fmt.Printf("Error reading client key file %v\n", err)
		return
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		fmt.Printf("Error reading client key as PRIVAT KEY %v\n", err)
		return
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Error reading client key ParsePKCS1PrivateKey %v\n", err)
		return
	}

	// caclulate the hash of the EKM
	h := sha256.New()
	h.Write(ekm)
	bs := h.Sum(nil)

	e := base64.RawURLEncoding.EncodeToString(bs)
	c := CNF{
		TBH: e,
	}
	fmt.Printf("EKM Hash %v\n", e)

	claims := &CustomClaimsExample{
		RegisteredClaims: &jwt.RegisteredClaims{

			IssuedAt:  &jwt.NumericDate{time.Now()},
			ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Second * 10)},
		},
		Scope: "https://www.googleapis.com/auth/cloud-platform",
		CNF:   c,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.Header["kid"] = "123456"
	tempAccessToken, err := token.SignedString(key)
	if err != nil {
		fmt.Printf("Error reading creating tempAccessToken %v\n", err)
		return
	}

	err = prettyPrintJWT(tempAccessToken)
	if err != nil {
		fmt.Printf("Error prettyprinting tempAccessToken %v\n", err)
		return
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tempAccessToken))

	///
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making request %v\n", err)
		return
	}

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error response %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf("%s\n", string(htmlData))

}

func prettyPrintJWT(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	fmt.Println("Header:")
	if err := prettyPrintPart(parts[0]); err != nil {
		return fmt.Errorf("error parsing header: %w", err)
	}

	fmt.Println("\nPayload:")
	if err := prettyPrintPart(parts[1]); err != nil {
		return fmt.Errorf("error parsing payload: %w", err)
	}

	return nil
}

func prettyPrintPart(encoded string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("error decoding base64: %w", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(decoded, &data); err != nil {
		return fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	formatted, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON for pretty print: %w", err)
	}

	fmt.Println(string(formatted))
	return nil
}
