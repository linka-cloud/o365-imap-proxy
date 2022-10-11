FROM golang:alpine as builder

WORKDIR /o365-imap-proxy

COPY go.mod go.sum ./

RUN go mod download

COPY cmd cmd
COPY pkg pkg

RUN CGO_ENABLED=0 go build -a -o o365-imap-proxy -ldflags="-s -w" ./cmd/o365-imap-proxy

FROM alpine

RUN apk add --no-cache ca-certificates

COPY --from=builder /o365-imap-proxy/o365-imap-proxy /usr/local/bin/

ENV TENANT="" \
    CLIENT_ID="" \
    CLIENT_SECRET="" \
    ADDRESS="" \
    DEBUG=""

EXPOSE 143

ENTRYPOINT ["/usr/local/bin/o365-imap-proxy"]
