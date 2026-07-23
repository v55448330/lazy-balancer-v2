FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1 as base
RUN apk add --no-cache ca-certificates curl

FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS xcaddy-builder
RUN apk add --no-cache git
ENV GOPROXY=https://goproxy.cn,direct
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.5
WORKDIR /app

ENV GOTOOLCHAIN=auto
RUN xcaddy build v2.11.4 \
  --with github.com/mholt/caddy-l4@v0.1.2 \
  --with github.com/caddyserver/transform-encoder

# Build Go backend
FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
WORKDIR /app/cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o lazy-balancer

# Build frontend
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS frontend
WORKDIR /app
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

# Final image
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1
ARG VERSION=2.0.3
ENV APP_VERSION=${VERSION}
RUN apk add --no-cache ca-certificates shadow sqlite tzdata
WORKDIR /app

COPY --from=xcaddy-builder /app/caddy /usr/local/bin/caddy
COPY --from=backend /app/cmd/server/lazy-balancer /usr/local/bin/lazy-balancer
COPY --from=frontend /app/dist /app/ui

RUN mkdir -p /app/data /app/config /app/logs /app/certs
RUN adduser -u 1000 -s /bin/sh -D -h /app caddy

COPY --from=backend /app/config /app/config

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80 443 8000 2019

ENTRYPOINT ["docker-entrypoint.sh"]
