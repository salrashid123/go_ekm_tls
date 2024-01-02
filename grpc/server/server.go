package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"

	echo "github.com/salrashid123/example/echo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	tlsCert  = flag.String("tlsCert", "../certs/server.crt", "tls Certificate")
	tlsKey   = flag.String("tlsKey", "../certs/server.key", "tls Key")
	grpcport = flag.String("grpcport", ":50051", "grpcport")
)

const (
	address string = ":50051"
)

type Server struct {
	mu sync.Mutex
	echo.UnimplementedEchoServerServer
}

func NewServer() *Server {
	return &Server{}
}

type contextKey string

func authUnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	//md, _ := metadata.FromIncomingContext(ctx)
	fmt.Printf("     TLS Peer IP Check")
	var newCtx context.Context
	peer, ok := peer.FromContext(ctx)
	if ok {
		peerIPPort, _, err := net.SplitHostPort(peer.Addr.String())
		if err != nil {
			fmt.Printf("ERROR:  Could get Remote IP %v", err)
			return nil, status.Errorf(codes.PermissionDenied, fmt.Sprintf("Could not get Remote IP   %v", err))
		}
		fmt.Printf("PeerIP: %s\n", peerIPPort)
		newCtx = context.WithValue(ctx, contextKey("peerIP"), peerIPPort)
	}

	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		fmt.Printf("ERROR:  Could get remote TLS")
		return nil, status.Errorf(codes.PermissionDenied, fmt.Sprintf("Could not get remote TLS"))
	}
	ekm, err := tlsInfo.State.ExportKeyingMaterial("my_nonce", nil, 32)
	if err != nil {
		fmt.Printf("ERROR:  Could getting EKM %v", err)
		return nil, status.Errorf(codes.PermissionDenied, fmt.Sprintf("Could getting EKM   %v", err))
	}
	fmt.Printf("EKM my_nonce: %s\n", hex.EncodeToString(ekm))
	newCtx = context.WithValue(newCtx, contextKey("ekm"), hex.EncodeToString(ekm))
	return handler(newCtx, req)
}

func (s *Server) SayHello(ctx context.Context, in *echo.EchoRequest) (*echo.EchoReply, error) {

	fmt.Printf("Got rpc: --> %s\n", in.Name)
	return &echo.EchoReply{Message: "Hello " + in.Name}, nil
}

func main() {
	flag.Parse()

	if *grpcport == "" {
		fmt.Println("missing -grpcport flag (:50051)")
		flag.Usage()

		os.Exit(1)
	}

	lis, err := net.Listen("tcp", *grpcport)
	if err != nil {
		fmt.Printf("failed to listen: %v", err)
		os.Exit(1)
	}

	sopts := []grpc.ServerOption{}

	ce, err := credentials.NewServerTLSFromFile(*tlsCert, *tlsKey)
	if err != nil {
		fmt.Printf("Failed to generate credentials %v", err)
		os.Exit(1)
	}
	sopts = append(sopts, grpc.Creds(ce))
	sopts = append(sopts, grpc.UnaryInterceptor(authUnaryInterceptor))
	s := grpc.NewServer(sopts...)
	srv := NewServer()

	echo.RegisterEchoServerServer(s, srv)

	fmt.Println("Starting Server...")
	s.Serve(lis)

}
