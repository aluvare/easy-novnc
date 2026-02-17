FROM golang:1.22-alpine3.19 AS build
RUN apk add --no-cache git
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o ./wstcp/wstcp ./wstcp

FROM alpine:3.19
RUN adduser -D -h /home/wstcp wstcp
COPY --from=build /src/wstcp/wstcp /
USER wstcp
EXPOSE 5900
ENTRYPOINT ["/wstcp"]
