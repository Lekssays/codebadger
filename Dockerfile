# Joern CLI container for CPG generation and caching.
# NOTE: base image is noble (Ubuntu 24.04, glibc 2.39), NOT jammy (22.04,
# glibc 2.35). rust2cpg's native astgen binary (rust_ast_gen-linux) is linked
# against GLIBC_2.39 and fails on jammy with "version `GLIBC_2.39' not found",
# silently yielding an empty Rust CPG. glibc is backward-compatible, so every
# other frontend's native astgen keeps working on noble.
FROM eclipse-temurin:21-jdk-noble

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

ENV JOERN_VERSION=4.0.581
ENV JOERN_HOME=/opt/joern

RUN mkdir -p ${JOERN_HOME} && \
    cd /tmp && \
    wget -q https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-install.sh && \
    chmod +x joern-install.sh && \
    sed -i 's/sudo //g' joern-install.sh && \
    ./joern-install.sh && \
    rm -rf joern-install.sh joern-cli.zip

ENV PATH="${JOERN_HOME}/joern-cli:${JOERN_HOME}/joern-cli/bin:${PATH}"

# Rust toolchain — rust2cpg's native astgen loads the crate by shelling out to
# `cargo`/`rustc` (it errors "Are `cargo` and `rustc` on your PATH?" otherwise),
# so without them every Rust CPG comes out empty. The minimal profile installs
# just rustc + cargo (no docs/clippy/rustfmt) to keep the layer small.
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/opt/cargo/bin:${PATH}"

RUN mkdir -p /playground

RUN joern --help && rustc --version && cargo --version

RUN echo '#!/bin/bash\n\
set -e\n\
tail -f /dev/null\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
