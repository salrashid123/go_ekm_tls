FROM golang:1.26.2 as build

RUN apt-get update -y && apt-get install -y build-essential wget unzip curl git

RUN curl -OL https://github.com/google/protobuf/releases/download/v3.19.0/protoc-3.19.0-linux-x86_64.zip && \
    unzip protoc-3.19.0-linux-x86_64.zip -d protoc3 && \
    mv protoc3/bin/* /usr/local/bin/ && \
    mv protoc3/include/* /usr/local/include/

WORKDIR /app

ADD . /app

RUN go mod download
RUN GO111MODULE=on 
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
RUN go install github.com/golang/protobuf/protoc-gen-go@latest

RUN /usr/local/bin/protoc --go_out=. --go_opt=paths=source_relative --go-grpc_opt=require_unimplemented_servers=false --go-grpc_out=. --go-grpc_opt=paths=source_relative echo/echo.proto

RUN go build -o server server/server.go
RUN go build -o client client/client.go

FROM gcr.io/distroless/base-debian12

COPY --from=build /app/certs/server.crt /certs
COPY --from=build /app/certs/server.key /certs
COPY --from=build /app/certs/client.crt /certs
COPY --from=build /app/certs/client.key /certs
COPY --from=build /app/certs/root-ca.crt /certs
COPY --from=build /app/server/server /
COPY --from=build /app/client/client /

EXPOSE 8080

ENTRYPOINT ["/server", "--grpcport=:8080"]