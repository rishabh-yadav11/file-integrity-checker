# Build stage: compile a static binary.
FROM golang:1.27.1-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/rishabh-yadav11/file-integrity-checker/cmd/ic/cmd.version=${VERSION}" \
    -o /out/integrity-check ./cmd/ic

# Runtime stage: distroless-style minimal image, non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/integrity-check /integrity-check
ENTRYPOINT ["/integrity-check"]
