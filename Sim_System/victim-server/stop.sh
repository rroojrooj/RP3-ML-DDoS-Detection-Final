#!/bin/bash
python3 /app/scripts/cleanup.py

# Define cleanup procedure
cleanup() {
    echo "Container stopped. Running scripts..."
    # echo "Stopped" > "c:\Users\YourName\Documents\NewFolder\myfile.txt"
    # python3 /app/scripts/pre_process.py
    # python3 /app/scripts/stop.py
}

# Trap SIGTERM signal
trap 'cleanup' SIGTERM

# Start tcpdump and Apache in the background
tcpdump -i any port 80 -w output/capture.pcap &
apache2ctl -D FOREGROUND &

# Wait for the background processes to finish
wait -n
