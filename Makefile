REGISTRY := docker.io
NAMESPACE := ctrox
INSTALLER_IMAGE := $(REGISTRY)/$(NAMESPACE)/zeropod-installer:dev
TEST_IMAGE := $(REGISTRY)/$(NAMESPACE)/zeropod-test:dev
CRIU_VERSION := v3.18
CRIU_IMAGE := $(REGISTRY)/$(NAMESPACE)/criu:$(CRIU_VERSION)
DOCKER_SOCK := /var/run/docker.sock

# build-kind can be used for fast local development. It just builds and
# switches out the shim binary. Running pods have to be recreated to make use
# of the new shim.
build-kind: build
	docker cp containerd-shim-zeropod-v2 kind-control-plane:/opt/zeropod/bin

install-kind: build-installer
	kind load docker-image ctrox/zeropod-installer:dev
	kubectl apply -f config/installer.yaml

build:
	CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o containerd-shim-zeropod-v2 .

logs:
	docker exec -ti kind-control-plane journalctl -fu containerd

build-criu:
	docker buildx build --push --platform linux/arm64,linux/amd64 -t $(CRIU_IMAGE) -f criu/Dockerfile .

build-installer:
	docker build --load -t $(INSTALLER_IMAGE) -f installer/Dockerfile .

build-test:
	docker build --load -t $(TEST_IMAGE) -f e2e/Dockerfile .

test-e2e:
	go test -v ./e2e/

bench:
	go test -bench=. -benchtime=10x -v -run=Bench ./e2e/

test:
	go test -v -short ./...

# docker-e2e runs the e2e test in a docker container. However, as running the
# e2e test requires a docker socket, this mounts the docker socket of the host
# into the container. For now this is the only way to run the e2e tests on Mac
# OS with apple silicon as the shim requires GOOS=linux.
docker-test-e2e: build-test
	docker run --rm -ti --privileged --network=host --rm -v $(DOCKER_SOCK):$(DOCKER_SOCK) -v $(PWD):/app $(TEST_IMAGE) make test-e2e

docker-bench: build-test
	docker run --rm -ti --privileged --network=host --rm -v $(DOCKER_SOCK):$(DOCKER_SOCK) -v $(PWD):/app $(TEST_IMAGE) make bench

# has to be privileged because the test tries to set netns
docker-test:
	docker run --rm -ti --privileged -v $(PWD):/app $(TEST_IMAGE) make test
