# syntax=docker/dockerfile:1.7
# Build context: clients/headless (never send the repository's SSH/runtime keys).
FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath -ldflags='-s -w' -o /heteronet-headless ./cmd/heteronet-headless

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /heteronet-headless /heteronet-headless
USER 65532:65532
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/heteronet-headless"]
