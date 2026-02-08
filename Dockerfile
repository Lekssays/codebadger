# Dockerfile for Joern Server Container
# Contains Joern CLI for CPG generation and caching

FROM eclipse-temurin:21-jdk-jammy

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Set Joern version
ENV JOERN_VERSION=4.0.478
ENV JOERN_HOME=/opt/joern

# Download and install Joern from joernio/joern GitHub releases
RUN mkdir -p ${JOERN_HOME} && \
    cd /tmp && \
    wget -q https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-install.sh && \
    chmod +x joern-install.sh && \
    sed -i 's/sudo //g' joern-install.sh && \
    ./joern-install.sh && \
    rm -rf joern-install.sh joern-cli.zip

# Add Joern CLI tools to PATH
ENV PATH="${JOERN_HOME}/joern-cli:${JOERN_HOME}/joern-cli/bin:${PATH}"

# Create playground directory for CPG storage
RUN mkdir -p /playground

# Verify Joern installation
RUN joern --help

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Keep container running\n\
tail -f /dev/null\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

# Run entrypoint script
CMD ["/entrypoint.sh"]
