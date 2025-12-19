#!/bin/sh
# Custom entrypoint with extensive logging

echo "=== ClamAV Custom Entrypoint Starting ==="

# Run the original entrypoint in background
/init &
INIT_PID=$!
echo "Started /init with PID: $INIT_PID"

# Wait for clamd to start (check for TCP port)
echo "Waiting for ClamAV clamd to start on port 3310..."
COUNTER=0
while ! nc -z localhost 3310 2>/dev/null; do
    sleep 1
    COUNTER=$((COUNTER + 1))
    if [ $COUNTER -ge 180 ]; then
        echo "ERROR: ClamAV failed to start TCP listener after 180s"
        exit 1
    fi
done

echo "=============================================="
echo "SUCCESS: ClamAV TCP listening on 0.0.0.0:3310"
echo "=============================================="

# Continuously monitor clamd status
while true; do
    sleep 30
    if nc -z localhost 3310 2>/dev/null; then
        echo "$(date): clamd TCP 3310 is UP"
    else
        echo "$(date): WARNING - clamd TCP 3310 is DOWN!"
        # Try to show what processes are running
        ps aux 2>/dev/null || true
    fi
done
