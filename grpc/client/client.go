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

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const ()

var (
	conn *grpc.ClientConn
)

func main() {

	address := flag.String("host", "localhost:50051", "host:port of gRPC server")
	serverName := flag.String("servername", "server.domain.com", "servername")
	tlsCert := flag.String("tlsCert", "../certs/root-ca.crt", "CACert for server")
	flag.Parse()

	var err error

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

	// Peer contains the method to extract the EKM.
	// however, Peer is only populated _after_ the rpc completes (not before)
	pr := new(peer.Peer)
	ce := credentials.NewTLS(tlsCfg)
	conn, err := grpc.Dial(*address, grpc.WithTransportCredentials(ce))

	// the only way i found to get the ekm first is to 'fake' the connection as if its not TLS..clearly, don't do this!
	// tconn, err := tls.Dial("tcp", "localhost:50051", &tlsCfg)
	// if err != nil {
	// 	fmt.Printf("Error dialing %v\n", err)
	// 	return
	// }
	// defer tconn.Close()
	// cs := tconn.ConnectionState()
	// tekm, err := cs.ExportKeyingMaterial("my_nonce", nil, 32)
	// if err != nil {
	// 	fmt.Printf("Error getting ekm %v\n", err)
	// 	return
	// }
	// fmt.Printf("EKM my_nonce: %s\n", hex.EncodeToString(tekm))
	// conn, err := grpc.Dial(*address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
	// 	return tconn, nil
	// }))

	if err != nil {
		fmt.Printf("did not connect: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	c := echo.NewEchoServerClient(conn)
	ctx := context.Background()

	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	r, err := c.SayHello(ctx, &echo.EchoRequest{Name: "unary RPC msg "}, grpc.Peer(pr))
	if err != nil {
		fmt.Printf("could not greet: %v", err)
		os.Exit(1)
	}
	fmt.Println(r)

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
		ekm, err := tlsInfo.State.ExportKeyingMaterial("my_nonce", nil, 32)
		if err != nil {
			fmt.Printf("ERROR:  Could getting EKM %v", err)
			os.Exit(1)
		}
		fmt.Printf("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

	default:
		fmt.Errorf("Unknown AuthInfo type")
		os.Exit(1)
	}

}
