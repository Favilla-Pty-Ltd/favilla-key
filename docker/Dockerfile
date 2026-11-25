# Reference build for Favilla KEY releases (24 Nov 2026).
#
# The same source at the same path with the same tools gives the same
# firmware.bin, whoever builds it. This image fixes the tools: Debian
# bookworm, Python 3.12, PlatformIO 6.1.18. platformio.ini pins the platform
# archive (ESP-IDF, Arduino core, GCC); dependencies.lock and
# scripts/pin_hybrid.py pin the components. The source is mounted at
# /favilla and PlatformIO lives at /pio, so paths are fixed too.
#
# Build the image once, then build a release (see REPRODUCE.md):
#   docker build -t favilla-build docker
#   docker run --rm -v "<your clone>:/favilla" favilla-build
# The G0 signer (Linux is its reference build, see REPRODUCE.md):
#   docker run --rm -v "<your clone>:/favilla" favilla-build sh -c "pio run -d g0 -e g0 && sha256sum g0/.pio/build/g0/firmware.bin"
FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates cmake ninja-build \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "platformio==6.1.18"

# the mounted clone belongs to another user; git must still read the commit
# time for SOURCE_DATE_EPOCH (scripts/build_epoch.py)
RUN git config --system --add safe.directory '*'

ENV PLATFORMIO_CORE_DIR=/pio
WORKDIR /favilla
CMD ["sh", "-c", "pio run -e favilla_key_fido_release && sha256sum .pio/build/favilla_key_fido_release/firmware.bin"]
