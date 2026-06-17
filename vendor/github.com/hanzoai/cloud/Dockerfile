FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /cloud ./cmd/cloud
FROM gcr.io/distroless/static
COPY --from=build /cloud /cloud
EXPOSE 8080 9090 9653
ENTRYPOINT ["/cloud"]
