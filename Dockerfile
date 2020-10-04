FROM golang:1.15 as build
WORKDIR /go/src/github.com/ccatp/authn-proxy
COPY . .
RUN go get -d -v
RUN go test -v
RUN CGO_ENABLED=0 GOOS=linux go install -a -v

FROM alpine:latest as certs
RUN apk --update add ca-certificates

FROM scratch
COPY --from=build /go/bin/authn-proxy /
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
CMD ["/authn-proxy"]
