FROM alpine:3.24.4
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/tldfinder /usr/local/bin/

ENTRYPOINT ["tldfinder"]
