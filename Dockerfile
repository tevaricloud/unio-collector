FROM python:3.12-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS builder

ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY . .
RUN python -m pip install --no-cache-dir "setuptools==83.0.0" "wheel==0.48.0" \
    && python -m pip install --no-cache-dir --require-hashes --prefix /opt/runtime -r requirements/container-runtime.lock \
    && python -m pip install --no-cache-dir --require-hashes -r requirements/container-runtime.lock \
    && python -m pip wheel --no-deps --no-build-isolation --wheel-dir /tmp/wheel . \
    && python -m pip install --no-cache-dir --no-deps --prefix /opt/runtime /tmp/wheel/unio_collector-*.whl

FROM python:3.12-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

RUN python -m pip uninstall --yes pip

ARG COLLECTOR_VERSION
ARG PUBLIC_SOURCE_SHA
ARG PUBLIC_SOURCE_TAG
LABEL org.opencontainers.image.title="Unio Collector" \
      org.opencontainers.image.description="Standalone read-only AWS evidence collector" \
      org.opencontainers.image.version="${COLLECTOR_VERSION}" \
      org.opencontainers.image.source="https://github.com/tevaricloud/unio-collector" \
      org.opencontainers.image.revision="${PUBLIC_SOURCE_SHA}" \
      org.opencontainers.image.ref.name="${PUBLIC_SOURCE_TAG}"

COPY --from=builder /opt/runtime /opt/runtime
RUN groupadd --gid 10001 unio_collector \
    && useradd --uid 10001 --gid 10001 --home-dir /home/unio --create-home --no-log-init unio_collector \
    && mkdir -p /work \
    && chown 10001:10001 /home/unio
ENV HOME=/home/unio TMPDIR=/tmp PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/runtime/lib/python3.12/site-packages \
    PATH=/opt/runtime/bin:$PATH
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/opt/runtime/bin/unio-collector"]
