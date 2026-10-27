FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libatomic1 \
    && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.source="https://github.com/IRus/telegram-mcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Send ChatGPT file attachments to named Telegram recipients through MCP"
WORKDIR /app
COPY --chmod=755 dist/telegram-mcp /app/telegram-mcp
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["/app/telegram-mcp"]
