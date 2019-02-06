
.PHONY: all
.DEFAULT: help

all:	test build

dep:
	go get -v -u github.com/golang/dep/cmd/dep

build:
	dep ensure && go build

test:
	go test -v ./...


