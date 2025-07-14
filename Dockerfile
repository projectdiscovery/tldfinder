# Base
FROM golang:1.24.5-alpine AS builder
RUN apk add --no-cache build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/tldfinder

# Release
FROM alpine:3.22.0
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/tldfinder /usr/local/bin/

ENTRYPOINT ["tldfinder"]