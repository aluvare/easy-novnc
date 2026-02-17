FROM golang:1.22-alpine3.19 AS build
ADD . /src
WORKDIR /src
RUN apk add --no-cache git
RUN go mod download
RUN go build -o ./wstcp/wstcp ./wstcp

FROM alpine:3.19
COPY --from=build /src/wstcp/wstcp /
EXPOSE 5900
ENTRYPOINT ["/wstcp"]
