package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"

	"os"
	"time"

	echo "github.com/salrashid123/example/echo"

	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/salrashid123/ekmcredential"
)

const ()

var (
	conn *grpc.ClientConn
)

func main() {

	address := flag.String("host", "localhost:50051", "host:port of gRPC server")
	serverName := flag.String("servername", "server.domain.com", "servername")
	tlsCert := flag.String("tlsCert", "certs/root-ca.crt", "CACert for server")
	flag.Parse()

	rootCAs := x509.NewCertPool()
	pem, err := os.ReadFile(*tlsCert)
	if err != nil {
		fmt.Printf("failed to load root CA certificates  error=%v", err)
		os.Exit(1)
	}
	if !rootCAs.AppendCertsFromPEM(pem) {
		fmt.Printf("no root CA certs parsed from file ")
		os.Exit(1)
	}

	tlsCfg := &tls.Config{
		ServerName: *serverName,
		RootCAs:    rootCAs,
	}

	ekmcreds, err := ekmcredential.NewCredentials(ekmcredential.Options{
		Secret:     []byte("secret"),
		EKMLabel:   "EXPORTER-my_label",
		EKMContext: []byte("mycontext"),
		EKMLength:  32,
	})
	if err != nil {
		fmt.Printf("error creating ekmcredential: %v", err)
		os.Exit(1)
	}

	ce := credentials.NewTLS(tlsCfg)
	sconn, err := grpc.NewClient(*address, grpc.WithTransportCredentials(ce), grpc.WithPerRPCCredentials(ekmcreds))
	if err != nil {
		fmt.Printf("did not create new TLS client: %v", err)
		os.Exit(1)
	}
	defer sconn.Close()

	c := echo.NewEchoServerClient(sconn)
	ctx := context.Background()

	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	pr := new(peer.Peer)
	r, err := c.SayHello(ctx, &echo.EchoRequest{Name: "unary RPC msg "}, grpc.Peer(pr))
	if err != nil {
		fmt.Printf("could not greet: %v", err)
		os.Exit(1)
	}
	fmt.Println(r.Message)

	/// get the EKM after the rpc when the peer is available

	switch info := pr.AuthInfo.(type) {
	case credentials.TLSInfo:
		authType := info.AuthType()
		sn := info.State.ServerName
		fmt.Printf("AuthType, ServerName %s, %s\n", authType, sn)
		tlsInfo, ok := pr.AuthInfo.(credentials.TLSInfo)
		if !ok {
			fmt.Printf("ERROR:  Could get remote TLS")
			os.Exit(1)
		}
		ekm, err := tlsInfo.State.ExportKeyingMaterial("EXPORTER-my_label", []byte("mycontext"), 32)
		if err != nil {
			fmt.Printf("ERROR:  Could getting EKM %v", err)
			os.Exit(1)
		}
		fmt.Printf("EKM EXPORTER-my_label: %s\n", hex.EncodeToString(ekm))

	default:
		fmt.Printf("Unknown AuthInfo type %v", info)
		os.Exit(1)
	}
	fmt.Println("return")

}
