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

COPY LICENSE /build/LICENSE
COPY ghidraMCP/build.gradle ghidraMCP/settings.gradle ghidraMCP/gradlew ./
COPY ghidraMCP/gradle ./gradle
COPY ghidraMCP/src ./src
COPY ghidraMCP/Module.manifest ghidraMCP/extension.properties ./
RUN GHIDRA_INSTALL_DIR=/opt/ghidra ./gradlew --no-daemon extensionZip \
    && mkdir -p /opt/ghidra/Ghidra/Extensions/ghidraMCP \
    && unzip -q build/distributions/ghidraMCP-0.1.0.zip -d /opt/ghidra/Ghidra/Extensions/ghidraMCP

FROM docker.io/library/eclipse-temurin:25-jdk
RUN apt-get update && apt-get install -y --no-install-recommends xvfb libxtst6 libxi6 libxrender1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/ghidra /opt/ghidra
COPY ghidraMCP/launch-mcp.sh /opt/ghidraMCP/launch-mcp.sh
COPY ghidraMCP/log4j-mcp.xml /opt/ghidraMCP/log4j-mcp.xml
COPY ghidraMCP/docker/entrypoint.sh /opt/ghidraMCP/entrypoint.sh
COPY ghidraMCP/docker/_code_browser.tcd /root/.config/ghidra/ghidra_12.2_PUBLIC/tools/_code_browser.tcd
RUN mkdir -p /root/.config/ghidra/ghidra_12.2_PUBLIC \
    && printf 'USER_AGREEMENT=ACCEPT\n' > /root/.config/ghidra/ghidra_12.2_PUBLIC/preferences \
    && chmod +x /opt/ghidraMCP/launch-mcp.sh /opt/ghidraMCP/entrypoint.sh
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
WORKDIR /data
ENTRYPOINT ["/opt/ghidraMCP/entrypoint.sh"]
