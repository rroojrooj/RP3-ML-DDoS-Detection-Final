# Use the latest Ubuntu image
FROM ubuntu:latest

# Install Apache and tcpdump
RUN apt-get update && apt-get install -y python3 python3-pip tshark

RUN pip3 install --break-system-packages pandas numpy scipy

# Create directories for scripts and output
RUN mkdir -p /app/scripts /output

# Copy the scripts into the container's /app/scripts directory
COPY pre_process.py /app/scripts/pre_process.py

# Execute the scripts when the container starts
CMD ["python3", "/app/scripts/pre_process.py"]
