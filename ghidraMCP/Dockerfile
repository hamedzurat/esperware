FROM docker.io/library/eclipse-temurin:25-jdk AS build

ARG GHIDRA_VERSION=12.2
ARG GHIDRA_BUILD=20261016
ARG GHIDRA_SHA256=2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67

WORKDIR /build/ghidraMCP
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip" -o ghidra.zip \
    && echo "${GHIDRA_SHA256}  ghidra.zip" | sha256sum -c - \
    && unzip -q ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra

COPY ghidraMCP/build.gradle ghidraMCP/settings.gradle ghidraMCP/gradlew ./
COPY ghidraMCP/gradle ./gradle
COPY ghidraMCP/src ./src
RUN GHIDRA_INSTALL_DIR=/opt/ghidra ./gradlew --no-daemon stageServer

FROM docker.io/library/eclipse-temurin:25-jdk
COPY --from=build /opt/ghidra /opt/ghidra
COPY --from=build /build/ghidraMCP/build/server /opt/ghidra-mcp
COPY ghidraMCP/bin/ghidra-mcp /opt/ghidra-mcp/bin/ghidra-mcp
COPY ghidraMCP/bin/log4j-headless.xml /opt/ghidra-mcp/bin/log4j-headless.xml
COPY wui /opt/ghidra-mcp/wui

RUN chmod +x /opt/ghidra-mcp/bin/ghidra-mcp \
    && mkdir -p /root/.config/ghidra/ghidra_12.2_PUBLIC \
    && printf 'USER_AGREEMENT=ACCEPT\n' > /root/.config/ghidra/ghidra_12.2_PUBLIC/preferences

ENV GHIDRA_INSTALL_DIR=/opt/ghidra \
    GHIDRA_MCP_HOME=/opt/ghidra-mcp \
    GHIDRA_MCP_WEBUI_DIR=/opt/ghidra-mcp/wui \
    GHIDRA_MCP_HOST=0.0.0.0 \
    GHIDRA_MCP_PORT=8765

WORKDIR /data
EXPOSE 8765
ENTRYPOINT ["/opt/ghidra-mcp/bin/ghidra-mcp"]
