.PHONY: setup build clean test docker

setup:
	@if [ ! -d novnc ]; then go run novnc_generate.go; fi

build: setup
	go build -o easy-novnc .

test: setup
	go test -v ./...

clean:
	rm -rf novnc/ easy-novnc

docker:
	docker build -t easy-novnc .
