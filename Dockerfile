FROM golang:1.22-alpine3.19 AS build
RUN apk add --no-cache git curl unzip
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go run novnc_generate.go
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o easy-novnc .

FROM alpine:3.19
RUN adduser -D -h /home/novnc novnc
COPY --from=build /src/easy-novnc /
USER novnc
EXPOSE 8080
ENTRYPOINT ["/easy-novnc"]
