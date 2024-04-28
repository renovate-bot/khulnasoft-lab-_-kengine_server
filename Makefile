VERSION?=$(shell git describe --tags)
GIT_COMMIT=$(shell git rev-parse HEAD)
BUILD_TIME=$(shell date -u +%FT%TZ)

all: kengine_server

local: kengine_server

image:
	docker run --rm -i -e VERSION=${VERSION} -e GIT_COMMIT=${GIT_COMMIT} -e BUILD_TIME=${BUILD_TIME} -v $(ROOT_MAKEFILE_DIR):/src:rw -v /tmp/go:/go:rw $(IMAGE_REPOSITORY)/kengine_builder_ce:$(DF_IMG_TAG) bash -c 'cd /src/kengine_server && make kengine_server'
	docker build -f ./Dockerfile -t $(IMAGE_REPOSITORY)/kengine_server_ce:$(DF_IMG_TAG) ..

vendor: go.mod $(shell find ../kengine_utils -path ../kengine_utils/vendor -prune -o -name '*.go')
	go mod tidy -v
	go mod vendor

kengine_server: vendor $(shell find . -path ./vendor -prune -o -name '*.go')
	go build -buildvcs=false -ldflags="-s -w -X github.com/khulnasoft-lab/kengine_server/pkg/constants.Version=${VERSION} -X github.com/khulnasoft-lab/kengine_server/pkg/constants.Commit=${GIT_COMMIT} -X github.com/khulnasoft-lab/kengine_server/pkg/constants.BuildTime=${BUILD_TIME}"

clean:
	-rm kengine_server
	-rm -rf ./vendor

.PHONY: all clean image local
