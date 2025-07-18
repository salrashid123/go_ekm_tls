## Exported Key Material (EKM) in golang and openssl

Snippet demonstrating how to extract and use TLS session `Exported Key Material (EKM)` as described in [RFC5705](https://datatracker.ietf.org/doc/html/rfc5705)


Each end of a TLS session can derive a unique key from the shared master secret which can be used for application-level protocol.


Basically, you can use the EKM to assert some application-level logic to the TLS session.  

Most commonly, this means is you can perform "Channel Binding" where with a client-server system.  For example:

1. `client`--> `TLS` --> `server`
2. client extracts the EKM on the connection
3. client issues a auth token (eg JWT/oidc token) where the EKM is a claim
4. client sends the JWT to the server
5. server verifies the JWT signature, extracts the ekm claim and compares it to the one from TLS

in this, the JWT token is only valid for that EKM/TLS session

You can ofcourse invert the flow where the server sends back a signed JWT which includes the EKM.  This will allow the client to verify the "server that issued the JWT knows about the EKM".

1. `client`--> `TLS` --> `server`
2. client extracts the EKM on the connection
3. client connects to the server at some rpc application endpoint (eg `/connect`) 
4. server extracts EKM from the connection
5. server issues a verifiable JWT where one of the claims is the EKM value
6. server sends the JWT back to the  client
7. client verifies the JWT signature, extracts the ekm claim and compares it to the one from TLS


The snippets below just shows how to extract the EKM in golang and openssl:

also see

* [TPM One Time Password using TLS SessionKey](https://github.com/salrashid123/tls_tpm_one_time_password)

### golang


#### HTTP

```bash
# first run the server
$ cd http/
$ go run server/main.go 

    Starting Server..
    EKM my_nonce from TLS: b47f680f2704d0351dfced758c19ce5ac95f2ac5e0c10575cb4e1b6bbfd69603
    EKM value from header b47f680f2704d0351dfced758c19ce5ac95f2ac5e0c10575cb4e1b6bbfd69603
    EKM value matches header

# then the client
$ go run client/main.go 

    EKM EXPORTER-my_label: b47f680f2704d0351dfced758c19ce5ac95f2ac5e0c10575cb4e1b6bbfd69603
    200 OK
    ok
```


#### HTTP with JWT Bound Token

This example covers the scenario for where client actually mints a JWT and encodes the current TLS session's EKM information.

For JWT, the example below uses the EKM encoded as `cnf.kid` as descrbed in [Representation of a Key ID for a Proof-of-Possession Key](https://datatracker.ietf.org/doc/html/rfc7800#section-3.4)


For example, if you run the client and server, you'll see something like this which prints out the JWT Bearer Token that is minted at the client.

```bash
$ go run client/main.go 

    EKM my_nonce: 4dfd59198bd38f9fd49f310822cd38c5f0bb108da9c17d523690abd37be9916b
    EKM Hash xxAEmVDM7JXaM--XpTytVgbcagwx7mQS529noQmWQfY
    Header:
    {
        "alg": "RS256",
        "kid": "123456",
        "typ": "JWT"
    }

    Payload:
    {
        "cnf": {
            "kid": "xxAEmVDM7JXaM--XpTytVgbcagwx7mQS529noQmWQfY"
        },
        "exp": 1743624913,
        "iat": 1743624903,
        "scope": "https://www.googleapis.com/auth/cloud-platform"
    }
    200 OK
    ok
```

The `cnf.tbh` is the the `b64url(sha256(ekm))` of the EKM


Server part extracts the EKM and parses/validates the Bearer JWT.  Then compares the `cnf.tbf` field and compares it to the EKM from TLS session.   If the values match, the request is accepted.

```bash
$ go run server/main.go 

    Starting Server..
    EKM  from TLS: 4dfd59198bd38f9fd49f310822cd38c5f0bb108da9c17d523690abd37be9916b
    Encoded EKM  from TLS: xxAEmVDM7JXaM--XpTytVgbcagwx7mQS529noQmWQfY
    JWT KeyID 123456
    EKM from Claim: xxAEmVDM7JXaM--XpTytVgbcagwx7mQS529noQmWQfY
    EKM matches

```

#### gRPC

See `grpc/` folder

To run

```bash
cd grpc/
$ go run server/server.go 

    Starting Server...
        TLS Peer IP CheckPeerIP: ::1
    EKM EXPORTER-my_label: 8be3055a4b7efbc4cb08f164ef4dbde191d8af02a7cc932b84490fa540bff0e4
    Got rpc: --> unary RPC msg 

$ go run client/client.go 

    message:"Hello unary RPC msg "
    AuthType, ServerName tls, server.domain.com
    EKM EXPORTER-my_label: 8be3055a4b7efbc4cb08f164ef4dbde191d8af02a7cc932b84490fa540bff0e4
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
  -ti docker.io/salrashid123/openssl s_server  -keymatexport EXPORTER-my_label -keymatexportlen 32  \
      -cert /certs/server.crt \
      -key /certs/server.key \
      -port 8081 \
      -CAfile /certs/root-ca.crt \
      -tlsextdebug \
      -tls1_3  \
      -trace 


docker run \
  --name client \
  --net=host \
  -v `pwd`/certs/:/certs \
  -ti docker.io/salrashid123/openssl s_client \
       -connect localhost:8081 -keymatexport EXPORTER-my_label -keymatexportlen 32 \
       -servername server.domain.com \
       -CAfile /certs/root-ca.crt \
       -tls1_3 \
       -tlsextdebug \
       -trace
```

you should see the same EKM value on both ends:

```bash
Keying material exporter:
    Label: 'EXPORTER-my_nonce'
    Length: 32 bytes
    Keying material: 5A142A3D156D91783A0A58D722C3EE36F5FA33D3EC01E8A2E3C0491169FDA279
```


You can also test the interop between `s_client` and the golang server.  Just note you need to `lowercase()` openssl's printout of the EKM and after connect, just add that to the header (since the server verifies the ekm provided)

eg, if s_client prints EKM as `E0B7671EE6ED6A124F2631025C40C5611659AEEA0CE710DB3097A9527AF1588B`, then on s_client connect just replay the http1.0 protocol and add the `ekm` header value:


```bash
GET /get HTTP/1.0
ekm: e0b7671ee6ed6a124f2631025c40c5611659aeea0ce710db3097a9527af1588b
```

Also see [Simple openssl c client/server which prints the Exported Key Material (EKM)](https://gist.github.com/salrashid123/8524f3c622794f3efb9b07a0b8b07bad)
