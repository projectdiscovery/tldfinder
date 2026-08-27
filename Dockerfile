# Base
FROM golang:1.27.0-alpine AS builder
RUN apk add --no-cache build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/tldfinder

# Release
FROM alpine:3.24.1
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/tldfinder /usr/local/bin/

ENTRYPOINT ["tldfinder"]