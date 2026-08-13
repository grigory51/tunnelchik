FROM golang:1.25 AS builder

ARG VERSION=dev
WORKDIR /src/tunnelchik
COPY tunnelchik/go.mod tunnelchik/go.sum ./
RUN go mod download
COPY tunnelchik/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.buildVersion=$VERSION" -o /out/tunnelchik .

FROM scratch

LABEL org.opencontainers.image.description="SSH gateway with ZITADEL authorization and session recording" \
      org.opencontainers.image.documentation="https://github.com/grigory51/tunnelchik/releases"
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/tunnelchik /tunnelchik

USER 65532:65532
EXPOSE 8022
ENTRYPOINT ["/tunnelchik"]
CMD ["--config", "/etc/tunnelchik/config.yaml"]
