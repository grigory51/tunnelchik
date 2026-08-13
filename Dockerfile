FROM golang:1.25 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tunnelchik .

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/tunnelchik /tunnelchik

USER 65532:65532
EXPOSE 8022
ENTRYPOINT ["/tunnelchik", "-config", "/etc/tunnelchik/config.yaml"]
