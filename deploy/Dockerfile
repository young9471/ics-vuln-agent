# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim AS web
WORKDIR /src/platform/web
COPY platform/web/package*.json ./
RUN npm ci
COPY platform/web/ ./
RUN NEXT_EXPORT=1 npm run build

FROM golang:1.26-bookworm AS build
WORKDIR /src/platform
COPY platform/go.mod platform/go.sum ./
COPY platform/norma ./norma
RUN go mod download
COPY platform/ ./
COPY --from=web /src/platform/web/out ./server/webui/dist
RUN go build -tags embedui -trimpath -ldflags "-s -w" -o /out/protocol-agent ./cmd/protocol-agent

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates tshark python3 python3-pip \
    && python3 -m pip install --no-cache-dir --break-system-packages pefile capstone \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app/platform
COPY --from=build /out/protocol-agent /app/platform/protocol-agent
COPY platform/skills /app/platform/skills
COPY platform/config.example.json /app/platform/config.example.json
COPY tools /app/tools
COPY deploy/docker-entrypoint.sh /app/deploy/docker-entrypoint.sh
RUN useradd --system --home /app --shell /usr/sbin/nologin protocol-agent \
    && mkdir -p /app/platform/data /app/platform/skills \
    && chown -R protocol-agent:protocol-agent /app
USER protocol-agent
ENV PROTOCOL_AGENT_SKILL_DIR=/app/platform/skills \
    PROTOCOL_AGENT_PROTOCOL_TOOLS_DIR=/app/tools \
    PROTOCOL_AGENT_PROTOCOL_RUNS_DIR=/app/platform/data/protocol_cases \
    PROTOCOL_AGENT_PROTOCOL_PYTHON=python3 \
    PROTOCOL_AGENT_PROTOCOL_TSHARK=tshark \
    PROTOCOL_AGENT_LISTEN=:8787
EXPOSE 8787
ENTRYPOINT ["/app/deploy/docker-entrypoint.sh"]
