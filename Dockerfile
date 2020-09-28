FROM golang:1.15-buster
WORKDIR /go/src/github.com/ccatp/auth-proxy
COPY . .
RUN go get -d -v
RUN go test -v
RUN go install -v

FROM debian:buster-slim
COPY --from=0 /go/bin/auth-proxy /usr/local/bin
CMD ["auth-proxy"]