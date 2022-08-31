# syntax = docker/dockerfile-upstream:1.2.0-labs

# THIS FILE WAS AUTOMATICALLY GENERATED, PLEASE DO NOT EDIT.
#
# Generated on 2022-08-31T10:23:45Z by kres latest.

ARG TOOLCHAIN

# runs markdownlint
FROM node:18.7.0-alpine AS lint-markdown
WORKDIR /src
RUN npm i -g markdownlint-cli@0.31.1
RUN npm i sentences-per-line@0.2.1
COPY .markdownlint.json .
COPY ./README.md ./README.md
RUN markdownlint --ignore "CHANGELOG.md" --ignore "**/node_modules/**" --ignore '**/hack/chglog/**' --rules node_modules/sentences-per-line/index.js .

# collects proto specs
FROM scratch AS proto-specs
ADD api/events/events.proto /api/events/
ADD api/siderolink/provision.proto /api/siderolink/

# base toolchain image
FROM ${TOOLCHAIN} AS toolchain
RUN apk --update --no-cache add bash curl build-base protoc protobuf-dev

# build tools
FROM toolchain AS tools
ENV GO111MODULE on
ENV CGO_ENABLED 0
ENV GOPATH /go
ARG GOLANGCILINT_VERSION
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCILINT_VERSION} \
	&& mv /go/bin/golangci-lint /bin/golangci-lint
ARG GOFUMPT_VERSION
RUN go install mvdan.cc/gofumpt@${GOFUMPT_VERSION} \
	&& mv /go/bin/gofumpt /bin/gofumpt
ARG GOIMPORTS_VERSION
RUN go install golang.org/x/tools/cmd/goimports@${GOIMPORTS_VERSION} \
	&& mv /go/bin/goimports /bin/goimports
ARG PROTOBUF_GO_VERSION
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v${PROTOBUF_GO_VERSION}
RUN mv /go/bin/protoc-gen-go /bin
ARG GRPC_GO_VERSION
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v${GRPC_GO_VERSION}
RUN mv /go/bin/protoc-gen-go-grpc /bin
ARG GRPC_GATEWAY_VERSION
RUN go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v${GRPC_GATEWAY_VERSION}
RUN mv /go/bin/protoc-gen-grpc-gateway /bin
ARG VTPROTOBUF_VERSION
RUN go install github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto@v${VTPROTOBUF_VERSION}
RUN mv /go/bin/protoc-gen-go-vtproto /bin
ARG DEEPCOPY_VERSION
RUN go install github.com/siderolabs/deep-copy@${DEEPCOPY_VERSION} \
	&& mv /go/bin/deep-copy /bin/deep-copy

# tools and sources
FROM tools AS base
WORKDIR /src
COPY ./go.mod .
COPY ./go.sum .
RUN --mount=type=cache,target=/go/pkg go mod download
RUN --mount=type=cache,target=/go/pkg go mod verify
COPY ./api ./api
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY ./pkg ./pkg
RUN --mount=type=cache,target=/go/pkg go list -mod=readonly all >/dev/null

# runs protobuf compiler
FROM tools AS proto-compile
COPY --from=proto-specs / /
RUN protoc -I/api --go_out=paths=source_relative:/api --go-grpc_out=paths=source_relative:/api --go-vtproto_out=paths=source_relative:/api --go-vtproto_opt=features=marshal+unmarshal+size /api/events/events.proto /api/siderolink/provision.proto
RUN rm /api/events/events.proto
RUN rm /api/siderolink/provision.proto
RUN goimports -w -local github.com/talos-systems/siderolink /api
RUN gofumpt -w /api

# runs gofumpt
FROM base AS lint-gofumpt
RUN FILES="$(gofumpt -l .)" && test -z "${FILES}" || (echo -e "Source code is not formatted with 'gofumpt -w .':\n${FILES}"; exit 1)

# runs goimports
FROM base AS lint-goimports
RUN FILES="$(goimports -l -local github.com/talos-systems/siderolink .)" && test -z "${FILES}" || (echo -e "Source code is not formatted with 'goimports -w -local github.com/talos-systems/siderolink .':\n${FILES}"; exit 1)

# runs golangci-lint
FROM base AS lint-golangci-lint
COPY .golangci.yml .
ENV GOGC 50
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/root/.cache/golangci-lint --mount=type=cache,target=/go/pkg golangci-lint run --config .golangci.yml

# runs unit-tests with race detector
FROM base AS unit-tests-race
ARG TESTPKGS
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg --mount=type=cache,target=/tmp CGO_ENABLED=1 go test -v -race -count 1 ${TESTPKGS}

# runs unit-tests
FROM base AS unit-tests-run
ARG TESTPKGS
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg --mount=type=cache,target=/tmp go test -v -covermode=atomic -coverprofile=coverage.txt -coverpkg=${TESTPKGS} -count 1 ${TESTPKGS}

# cleaned up specs and compiled versions
FROM scratch AS generate
COPY --from=proto-compile /api/ /api/

FROM scratch AS unit-tests
COPY --from=unit-tests-run /src/coverage.txt /coverage.txt

# builds siderolink-agent-darwin-amd64
FROM base AS siderolink-agent-darwin-amd64-build
COPY --from=generate / /
WORKDIR /src/cmd/siderolink-agent
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg GOARCH=amd64 GOOS=darwin go build -ldflags "-s -w" -o /siderolink-agent-darwin-amd64

# builds siderolink-agent-darwin-arm64
FROM base AS siderolink-agent-darwin-arm64-build
COPY --from=generate / /
WORKDIR /src/cmd/siderolink-agent
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg GOARCH=arm64 GOOS=darwin go build -ldflags "-s -w" -o /siderolink-agent-darwin-arm64

# builds siderolink-agent-linux-amd64
FROM base AS siderolink-agent-linux-amd64-build
COPY --from=generate / /
WORKDIR /src/cmd/siderolink-agent
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg GOARCH=amd64 GOOS=linux go build -ldflags "-s -w" -o /siderolink-agent-linux-amd64

# builds siderolink-agent-linux-arm64
FROM base AS siderolink-agent-linux-arm64-build
COPY --from=generate / /
WORKDIR /src/cmd/siderolink-agent
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg GOARCH=arm64 GOOS=linux go build -ldflags "-s -w" -o /siderolink-agent-linux-arm64

# builds siderolink-agent-linux-armv7
FROM base AS siderolink-agent-linux-armv7-build
COPY --from=generate / /
WORKDIR /src/cmd/siderolink-agent
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg GOARCH=arm GOARM=7 GOOS=linux go build -ldflags "-s -w" -o /siderolink-agent-linux-armv7

# builds siderolink-agent-windows-amd64.exe
FROM base AS siderolink-agent-windows-amd64.exe-build
COPY --from=generate / /
WORKDIR /src/cmd/siderolink-agent
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg GOARCH=amd64 GOOS=windows go build -ldflags "-s -w" -o /siderolink-agent-windows-amd64.exe

FROM scratch AS siderolink-agent-darwin-amd64
COPY --from=siderolink-agent-darwin-amd64-build /siderolink-agent-darwin-amd64 /siderolink-agent-darwin-amd64

FROM scratch AS siderolink-agent-darwin-arm64
COPY --from=siderolink-agent-darwin-arm64-build /siderolink-agent-darwin-arm64 /siderolink-agent-darwin-arm64

FROM scratch AS siderolink-agent-linux-amd64
COPY --from=siderolink-agent-linux-amd64-build /siderolink-agent-linux-amd64 /siderolink-agent-linux-amd64

FROM scratch AS siderolink-agent-linux-arm64
COPY --from=siderolink-agent-linux-arm64-build /siderolink-agent-linux-arm64 /siderolink-agent-linux-arm64

FROM scratch AS siderolink-agent-linux-armv7
COPY --from=siderolink-agent-linux-armv7-build /siderolink-agent-linux-armv7 /siderolink-agent-linux-armv7

FROM scratch AS siderolink-agent-windows-amd64.exe
COPY --from=siderolink-agent-windows-amd64.exe-build /siderolink-agent-windows-amd64.exe /siderolink-agent-windows-amd64.exe

FROM siderolink-agent-linux-${TARGETARCH} AS siderolink-agent

