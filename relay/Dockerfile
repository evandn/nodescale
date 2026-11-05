# nodescale relay — runs as a Cloudflare Container (see apps/console/wrangler.jsonc).
FROM golang:1.24-alpine AS build
ENV GOTOOLCHAIN=auto CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags "-s -w" -o /out/nodescale-relay .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nodescale-relay /usr/local/bin/nodescale-relay
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/nodescale-relay"]
