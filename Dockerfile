# 公式イメージ（design.md 11.11、13.8、ADR 0073）。
#   全部入り: docker build -t iam .
#   最小構成: docker build --build-arg BUILD_SPEC=build/minimal.yaml -t iam:minimal .
# 自分の構成は build.yaml を置いて BUILD_SPEC に指定する。
FROM golang:1.27@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS build
WORKDIR /src
COPY . .
ARG BUILD_SPEC=""
ARG VERSION=dev
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    cd cmd/iam && \
    if [ -n "$BUILD_SPEC" ]; then \
      go run . build -f "/src/$BUILD_SPEC" -o /out/iam -version "$VERSION"; \
    else \
      go build -trimpath -ldflags "-X main.version=$VERSION" -o /out/iam .; \
    fi && \
    /out/iam version -manifest > /out/manifest.json

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/iam /usr/local/bin/iam
COPY --from=build /out/manifest.json /usr/share/iam/manifest.json
USER nonroot:nonroot
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/iam"]
CMD ["serve", "-config", "/etc/iam/iam.yaml"]
