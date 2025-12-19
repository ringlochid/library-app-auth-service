#!/bin/sh
# Custom entrypoint that logs TCP status

# Run the original entrypoint in background
/init &

# Wait for clamd to start (check for TCP port)
echo "Waiting for ClamAV to start..."
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

# Keep container running
wait
