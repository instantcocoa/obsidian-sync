# obsync server image: a static binary on a distroless base, run as the
# unprivileged "nonroot" user (uid 65532). Build from the server/ directory:
#   docker build -t obsync .
# Data lives wherever /data is mounted; see deploy/ for the compose file.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /obsync ./cmd/obsync

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /obsync /usr/local/bin/obsync
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/obsync"]
CMD ["serve", "--data", "/data", "--listen", "0.0.0.0:8080"]
