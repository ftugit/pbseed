# PocketBase + seed(ed25519) auth (Go).
# Build:  docker build -t pbseed .
# Run:    docker run -p 8090:8090 -v pbseed_data:/pb/pb_data pbseed
# Ephemeral disk without volumes (e.g. Northflank Sandbox)? Build with
# Dockerfile.r2 instead — the same app plus a litestream sidecar to R2.

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# static binary, no CGO (PocketBase uses a pure-Go SQLite driver)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /pbseed .

FROM alpine:3
RUN apk add --no-cache ca-certificates
WORKDIR /pb
COPY --from=build /pbseed /pb/pbseed
EXPOSE 8090
ENTRYPOINT ["/pb/pbseed"]
CMD ["serve", "--http=0.0.0.0:8090", "--dir=/pb/pb_data"]
