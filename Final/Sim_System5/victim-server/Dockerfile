# Use the latest Ubuntu image
FROM ubuntu:latest

# Install Apache and tcpdump
RUN apt-get update && apt-get install -y apache2 tcpdump python3

# Create directories for scripts and output
RUN mkdir -p /app/scripts /output

# Copy the scripts into the container's /app/scripts directory
COPY stop.sh /app/scripts/stop.sh
COPY cleanup.py /app/scripts/cleanup.py

# Make the scripts executable
RUN chmod +x /app/scripts/stop.sh /app/scripts/cleanup.py

# Expose port 80 for HTTP traffic
EXPOSE 80

# Set the entry point to the stop.sh script in /app/scripts
ENTRYPOINT ["/app/scripts/stop.sh"]