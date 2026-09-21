# Sentinel firmware analysis environment.
#
# Firmware extractors are the least trustworthy code in this pipeline. unblob
# and binwalk delegate to a long tail of third-party extractors, several of
# which will write outside the output directory when handed a malformed
# archive -- and vendor images are malformed as a matter of routine. That is
# the reason this container exists, not convenience.
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Extraction toolchain. unblob shells out to most of these; run
# `unblob --show-external-dependencies` after building to see what it still
# cannot find, since the list moves between releases.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git curl ca-certificates \
      p7zip-full unar zstd lz4 lzop xz-utils lziprecover \
      e2fsprogs erofs-utils zlib1g-dev liblzo2-dev libucl-dev \
      device-tree-compiler cpio \
      qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 \
      binutils file \
  && rm -rf /var/lib/apt/lists/*

# Go, for the worker binaries.
ARG GO_VERSION=1.23.4
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
      -o /tmp/go.tgz \
 && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# sasquatch handles the vendor-patched squashfs variants that mainstream
# unsquashfs rejects. Most consumer router images need it; without it the
# rootfs stage will fail and you will wrongly blame the image.
RUN git clone --depth 1 https://github.com/onekey-sec/sasquatch /tmp/sasquatch \
 && cd /tmp/sasquatch && ./build.sh && rm -rf /tmp/sasquatch \
 || echo "sasquatch build failed; squashfs coverage will be reduced"

WORKDIR /work
COPY . /work
RUN go build -o bin/elfscan ./go/elfscan || true

# Non-root by default. The pipeline never needs privilege, and extraction
# running as root is how a path traversal in a vendor archive becomes a host
# compromise.
RUN useradd -m -u 1000 sentinel && chown -R sentinel:sentinel /work
USER sentinel

CMD ["python3", "-m", "sentinel.cli", "--help"]
