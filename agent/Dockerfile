# nodescale agent — runs on every managed server, next to the Docker daemon.
# It is built from the Go standard library only: no third-party code ever
# touches the Docker socket.
FROM golang:1.24-alpine AS build
ARG VERSION=dev
ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go test ./... && \
    go build -trimpath -ldflags "-s -w -X github.com/evandn/nodescale/agent/internal/agent.Version=${VERSION}" \
      -o /out/nodescale-agent ./cmd/nodescale-agent

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/nodescale-agent /usr/local/bin/nodescale-agent
# Containers carrying this label cannot be stopped or removed through nodescale.
LABEL io.nodescale.role="agent" \
      org.opencontainers.image.source="https://github.com/evandn/nodescale" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["/usr/local/bin/nodescale-agent"]
CMD ["serve"]
