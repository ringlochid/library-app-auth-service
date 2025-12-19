# ClamAV with TCP enabled for cross-container communication
FROM clamav/clamav:stable

# Install netcat for TCP check in entrypoint
RUN apk add --no-cache netcat-openbsd

# Copy custom config that enables TCP on 0.0.0.0:3310
COPY clamd.conf /etc/clamav/clamd.conf

# Copy custom entrypoint that logs TCP status
COPY entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh

ENTRYPOINT ["/custom-entrypoint.sh"]