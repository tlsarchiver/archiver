all: build-image

bake-archiver:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-s' -o archiver .

build-image: bake-archiver
	docker build -t tlsarchiver/archiver .

upload-image: build-image
	docker push tlsarchiver/archiver

# Dependencies for linting Go code
golint_deps:
	go get -u github.com/kisielk/errcheck
	go get -u github.com/golang/lint/golint
	go get -u github.com/opennota/check/cmd/aligncheck
	go get -u github.com/opennota/check/cmd/structcheck
	go get -u github.com/opennota/check/cmd/varcheck
	go get -u github.com/gordonklaus/ineffassign
	go get -u github.com/mdempsky/unconvert
	go get -u honnef.co/go/simple/cmd/gosimple
	go get -u honnef.co/go/staticcheck/cmd/staticcheck

deps:
	go get -u github.com/lib/pq
	go get -u github.com/tlsarchiver/dbconnector

# Perform static checks on the Go code
# See new ideas at https://github.com/alecthomas/gometalinter
golint:
	go fmt -n | sed -e "s/gofmt -l/gofmt -s -l/g" | sh
	golint
	go tool vet -all -shadow ./
	aligncheck
	structcheck
	varcheck
	# errcheck -ignoretests
	ineffassign ./
	unconvert
	gosimple
	staticcheck
