# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.25 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/api ./cmd/api
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/worker ./cmd/worker

# --- runtime stage ---
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /out/api /app/api
COPY --from=build /out/worker /app/worker
COPY --from=build /src/migrations /app/migrations
COPY --from=build /src/contracts /app/contracts
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/app/api"]
