# syntax=docker/dockerfile:1.7

ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

FROM ${DEBIAN_IMAGE} AS fetch
ARG TARGETARCH
ARG GRAIN_VERSION=v0.7.1
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && case "${TARGETARCH}" in \
        amd64) \
            asset=grain-linux-amd64.tar.gz; \
            sha256=e000dad4c35669a32284a66876b6171e23fee2a12bfbfcce7824ebc3316a602d \
            ;; \
        arm64) \
            asset=grain-linux-arm64.tar.gz; \
            sha256=80afc9a808ed8cde16c8e0ded349cba0801337ff0fd8a119842909fe085a6622 \
            ;; \
        *) echo "unsupported target architecture: ${TARGETARCH}" >&2; exit 64 ;; \
    esac \
    && curl --fail --location --proto '=https' --tlsv1.2 \
        "https://github.com/0ceanSlim/grain/releases/download/${GRAIN_VERSION}/${asset}" \
        --output /tmp/grain.tar.gz \
    && printf '%s  %s\n' "${sha256}" /tmp/grain.tar.gz | sha256sum --check --strict \
    && mkdir /out /tmp/grain \
    && tar --extract --gzip --file /tmp/grain.tar.gz --directory /tmp/grain --strip-components 1 \
    && install --mode 0555 /tmp/grain/grain /out/grain

FROM ${DEBIAN_IMAGE}
ARG GRAIN_VERSION=v0.7.1
LABEL org.opencontainers.image.title="OmaChat Grain relay candidate" \
      org.opencontainers.image.description="Pinned Grain bootstrap candidate; not production approval" \
      org.opencontainers.image.source="https://github.com/0ceanSlim/grain" \
      org.opencontainers.image.version="${GRAIN_VERSION}" \
      org.opencontainers.image.revision="c0709db6e59d57620ba2053c7078b1e07942d38c"
COPY --from=fetch /out/grain /usr/local/bin/grain
COPY --from=fetch /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0555 container-entrypoint.sh /usr/local/bin/omachat-grain-entrypoint
COPY config.yml relay_metadata.json whitelist.yml blacklist.yml /etc/omachat-grain/
RUN install --directory --mode 0750 --owner 65532 --group 65532 /var/lib/grain
USER 65532:65532
WORKDIR /var/lib/grain
EXPOSE 8181
ENTRYPOINT ["/usr/local/bin/omachat-grain-entrypoint"]
