#!/bin/bash

# === User-Adjustable Parameters ===
VICTIM="localhost"

MIN_CONNECTIONS=10     # Minimum concurrent connections per batch
MAX_CONNECTIONS=25    # Maximum concurrent connections per batch

MIN_SLEEP=1           # Minimum seconds between batches
MAX_SLEEP=3           # Maximum seconds between batches

# ==================================

echo "Simulating randomized parallel traffic to $VICTIM..."
echo "Connections per batch: $MIN_CONNECTIONS-$MAX_CONNECTIONS"
echo "Sleep interval: $MIN_SLEEP-$MAX_SLEEP seconds"

while true; do
    CONNECTIONS=$(shuf -i "$MIN_CONNECTIONS"-"$MAX_CONNECTIONS" -n 1)
    echo "Starting batch with $CONNECTIONS concurrent connections."

    for ((i=1; i<=CONNECTIONS; i++)); do
        (
            curl -s -o /dev/null -w "Request $i response: %{http_code}\n" "http://$VICTIM"
        ) &
    done

    wait  # Wait until all parallel requests complete

    SLEEP_TIME=$(awk -v min="$MIN_SLEEP" -v max="$MAX_SLEEP" 'BEGIN{srand(); print min+rand()*(max-min)}')
    echo "Batch complete. Sleeping for $SLEEP_TIME seconds."
    sleep "$SLEEP_TIME"
done
