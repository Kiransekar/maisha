# Turnkey Maisha: the CLI + MCP server with the free analyzers (cppcheck's MISRA
# addon + clang-tidy) already installed, so `docker run` gives a working
# MISRA/CERT/BARR-C compliance stack with zero host setup.
FROM python:3.12-slim

# Free analyzers so the image is self-contained (native analyzer needs nothing).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cppcheck clang-tidy \
    && rm -rf /var/lib/apt/lists/*

# Install only what the package needs to build/install (keeps the image lean).
COPY pyproject.toml README.md LICENSE /src/
COPY maishac /src/maishac
RUN pip install --no-cache-dir /src

# Mount your project here: `docker run -v "$PWD:/work" ghcr.io/winterlabshq/maisha scan src/`
WORKDIR /work
ENTRYPOINT ["maishac"]
CMD ["--help"]
