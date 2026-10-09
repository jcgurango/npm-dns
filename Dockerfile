FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /npm-dns .

FROM alpine:3.20
COPY --from=build /npm-dns /usr/local/bin/npm-dns
ENV NPM_DATA=/data/nginx LISTEN=:53
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["npm-dns"]
