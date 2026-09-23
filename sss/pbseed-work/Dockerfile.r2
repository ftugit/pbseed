# pbseed + litestream sidecar (Cloudflare R2 durability for ephemeral disks).
# Build:  docker build -f Dockerfile.r2 -t pbseed:r2 .
# Run:    docker run -p 8090:8090 \
#           -e R2_ACCOUNT_ID=.. -e R2_BUCKET=.. \
#           -e R2_ACCESS_KEY_ID=.. -e R2_SECRET_ACCESS_KEY=.. pbseed:r2
# Without the R2_* vars the app still starts (directly, ephemeral disk).
# Have a real volume (VDS, paid Northflank volume)? Use plain Dockerfile —
# or keep this one anyway as an offsite backup (single instance only).

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
# litestream sidecar: streams data.db to R2 (see entrypoint.sh).
# Pinned release + sha256 (immutable URL, guards against drift).
ADD https://github.com/benbjohnson/litestream/releases/download/v0.5.17/litestream-0.5.17-linux-x86_64.tar.gz /tmp/litestream.tar.gz
RUN echo "cfb371176d164437ae869f8351cfde49bd1804ae71c61923f75c9cba9c9c006d  /tmp/litestream.tar.gz" | sha256sum -c - \
  && tar xzf /tmp/litestream.tar.gz -C /tmp \
  && mv /tmp/litestream /pb/litestream && rm -f /tmp/litestream.tar.gz \
  && /pb/litestream version
COPY entrypoint.sh litestream.yml /pb/
RUN chmod +x /pb/entrypoint.sh
EXPOSE 8090
ENTRYPOINT ["/pb/entrypoint.sh"]
CMD ["/pb/pbseed", "serve", "--http=0.0.0.0:8090", "--dir=/pb/pb_data"]
