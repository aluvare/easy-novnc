FROM golang:1.22-alpine3.19 AS build
RUN apk add --no-cache git curl unzip
ADD . /src
WORKDIR /src
RUN go run novnc_generate.go
RUN go build -o easy-novnc .

FROM alpine:3.19
COPY --from=build /src/easy-novnc /
EXPOSE 8080
ENTRYPOINT ["/easy-novnc"]
