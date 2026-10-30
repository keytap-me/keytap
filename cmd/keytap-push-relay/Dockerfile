# keytap-push-relay — static Go binary on distroless (no shell, no package manager), non-root.
# Base images pinned by digest; bump deliberately.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN go vet ./... && go test ./... && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/keytap-push-relay .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/keytap-push-relay /keytap-push-relay
ARG CI_COMMIT_SHA
ENV CI_COMMIT_SHA=$CI_COMMIT_SHA
LABEL org.opencontainers.image.source="https://github.com/keytap-me/keytap"
LABEL ci.commit.sha=$CI_COMMIT_SHA
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/keytap-push-relay"]
