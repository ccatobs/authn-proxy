FROM golang:1.15
WORKDIR /go/src/github.com/ccatp/authn-proxy
COPY . .
RUN go get -d -v
RUN go test -v
RUN CGO_ENABLED=0 GOOS=linux go install -a -v

FROM scratch
COPY --from=0 /go/bin/authn-proxy /
CMD ["/authn-proxy"]
