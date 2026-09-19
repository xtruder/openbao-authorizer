# syntax=docker/dockerfile:1

FROM node:24-alpine AS web-build
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.0-alpine AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-build /src/web/dist ./web/dist
ARG TARGETOS=linux
ARG TARGETARCH
RUN test -n "${TARGETARCH}" && \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags='-s -w' -o /out/openbao-authorizer ./cmd/server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 65532 authorizer && \
    adduser -S -D -H -u 65532 -G authorizer authorizer
COPY --from=go-build --chown=65532:65532 /out/openbao-authorizer /usr/local/bin/openbao-authorizer
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/openbao-authorizer"]
