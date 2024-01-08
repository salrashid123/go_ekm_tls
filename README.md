## Exported Key Material (EKM) in golang and openssl

Snippet demonstrating how to extract and use TLS session `Exported Key Material (EKM)` as described in [RFC5705](https://datatracker.ietf.org/doc/html/rfc5705)


Each end of a TLS session can derive a unique key from the shared master secret which can be used for application-level protocol.


Basically, you can use the EKM to assert some application-level logic to the TLS session.  

Most commonly, this means is you can perform "Channel Binding" where with a client-server system.  For example:

1. client --> TLS --> server
2. client extracts the EKM on the connection
3. client issues a auth token (eg JWT/oidc token) where the EKM is a claim
4. client sends the JWT to the server
5. server verifies the JWT signature, extracts the ekm claim and compares it to the one from TLS

in this, the JWT token is only valid for that EKM/TLS session

You can ofcourse invert the flow where the server sends back a signed JWT which includes the EKM.  This will allow the client to verify the "server that issued the JWT knows about the EKM".

1. client --> TLS --> server
2. client extracts the EKM on the connection
3. client connects to the server at some rpc application endpoint (eg `/connect`) 
4. server extracts EKM from the connection
5. server issues a verifiable JWT where one of the claims is the EKM value
6. server sends the JWT back to the  client
7. client verifies the JWT signature, extracts the ekm claim and compares it to the one from TLS


The snippets below just shows how to extract the EKM in golang and openssl:

### golang


#### HTTP

```bash
# first run the server
$ cd http/
$ go run server/main.go 
Starting Server..
EKM my_nonce from TLS: 18f437fad46d7b4224fba3fe429bee4a83681a4d0157ec56b424c0939a227708
EKM value from header 18f437fad46d7b4224fba3fe429bee4a83681a4d0157ec56b424c0939a227708
EKM value matches header

# then the client
$ go run client/main.go 
EKM my_nonce: 18f437fad46d7b4224fba3fe429bee4a83681a4d0157ec56b424c0939a227708
200 OK
ok
```

#### gRPC

See `grpc/` folder

To run

```bash
cd grpc/
$ go run server/server.go 
Starting Server...
     TLS Peer IP CheckPeerIP: 127.0.0.1
EKM my_nonce: b0586f514325aab325b72bb8745de166bb34dbec722356878d7b0fc65f7aa49d
Got rpc: --> unary RPC msg 

$ go run client/client.go 
message:"Hello unary RPC msg   from hostname "
AuthType, ServerName tls, server.domain.comEKM my_nonce: b0586f514325aab325b72bb8745de166bb34dbec722356878d7b0fc65f7aa49d
```

also see

* [go_mtls_scratchpad Exported Key Material](https://github.com/salrashid123/go_mtls_scratchpad/tree/main#exported-key-material)


### OpenSSL

Openssl's `s_client/s_server` allows you to set and print out the EKM value as well

See [SSL_export_keying_material](https://www.openssl.org/docs/man1.1.1/man3/SSL_export_keying_material.html) exposed using the `-keymatexport` and `-keymatexportlen` parameters

The following runs a small debug-enabled openssl3 container (yes 3, without the patch) from [OpenSSL 3.0.0 docker with TLS trace enabled (enable-ssl-trace) and FIPS (enable-fips)](https://github.com/salrashid123/openssl_trace/tree/main)

first run the client and server (to stop run `docker rm -f client server`)

```bash
 docker run \
  --name server \
  -p 8081:8081 \
  --net=host \
  -v `pwd`/certs:/certs \
  -ti docker.io/salrashid123/openssl s_server  -keymatexport my_nonce -keymatexportlen 32  \
      -cert /certs/server.crt \
      -key /certs/server.key \
      -port 8081 \
      -CAfile /certs/tls-ca-chain.pem \
      -tlsextdebug \
      -tls1_3  \
      -trace 


docker run \
  --name client \
  --net=host \
  -v `pwd`/certs/:/certs \
  -ti docker.io/salrashid123/openssl s_client \
       -connect localhost:8081 -keymatexport my_nonce -keymatexportlen 32 \
       -servername server.domain.com \
       -CAfile /certs/tls-ca-chain.pem \
       -tls1_3 \
       -tlsextdebug \
       -trace
```

you should see the same EKM value on both ends:

```bash
Keying material exporter:
    Label: 'my_nonce'
    Length: 32 bytes
    Keying material: 5A142A3D156D91783A0A58D722C3EE36F5FA33D3EC01E8A2E3C0491169FDA279
```


You can also test the interop between `s_client` and the golang server.  Just note you need to `lowercase()` openssl's printout of the EKM and after connect, just add that to the header (since the server verifies the ekm provided)

eg, if s_client prints EKM as `E0B7671EE6ED6A124F2631025C40C5611659AEEA0CE710DB3097A9527AF1588B`, then on s_client connect just replay the http1.0 protocol and add the `ekm` header value:


```bash
GET /get HTTP/1.0
ekm: e0b7671ee6ed6a124f2631025c40c5611659aeea0ce710db3097a9527af1588b
```


