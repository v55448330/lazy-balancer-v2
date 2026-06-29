FROM alpine:3.19 as base
RUN apk add --no-cache ca-certificates curl

FROM golang:1.26.1-alpine AS xcaddy-builder
RUN apk add --no-cache git
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.5
WORKDIR /app

ENV GOTOOLCHAIN=auto
RUN xcaddy build v2.11.4 \
  --with github.com/caddy-dns/dnspod@fb7cc31cc04c68a304b8d2672c3e5d9f2ad3d7ba \
  --with github.com/mholt/caddy-l4@v0.1.1

# Build Go backend
FROM golang:1.21-alpine AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
WORKDIR /app/cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o lazy-balancer

# Build frontend
FROM node:20-alpine AS frontend
WORKDIR /app
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

# Final image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates shadow
WORKDIR /app

COPY --from=xcaddy-builder /app/caddy /usr/local/bin/caddy
COPY --from=backend /app/cmd/server/lazy-balancer /usr/local/bin/lazy-balancer
COPY --from=frontend /app/dist /app/ui

RUN mkdir -p /app/data /app/config
RUN adduser -u 1000 -s /bin/sh -D -h /app caddy

COPY --from=backend /app/config /app/config

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80 443 8000 2019

ENTRYPOINT ["docker-entrypoint.sh"]
