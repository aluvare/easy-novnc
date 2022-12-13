FROM golang:1.20rc1-alpine3.17 AS build
ADD . /src
WORKDIR /src
RUN apk add --no-cache git
RUN go mod tidy && go mod vendor
RUN go build .
RUN go run index_generate.go
RUN go run novnc_generate.go && sed -i "s/noVNC-add_clipboard_support/noVNC-master/g" novnc_generated.go

FROM alpine:3.17
COPY --from=build /src/easy-novnc /
EXPOSE 8080
ENTRYPOINT ["/easy-novnc"]
