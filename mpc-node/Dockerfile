FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /mpc-node ./cmd/mpc-node

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /mpc-node /usr/local/bin/mpc-node
RUN adduser -D -u 1000 mpc
USER mpc
VOLUME /data/kms-mpc
EXPOSE 9651
ENTRYPOINT ["mpc-node"]
CMD ["serve"]
