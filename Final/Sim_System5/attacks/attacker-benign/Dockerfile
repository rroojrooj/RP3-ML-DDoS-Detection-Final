FROM kalilinux/kali-rolling

# Install required tools
RUN apt-get update && apt-get install -y curl

# Copy and set permissions for traffic script
COPY normal_traffic.sh /normal_traffic.sh
RUN chmod +x /normal_traffic.sh

# Run traffic script automatically
CMD ["/bin/bash", "/normal_traffic.sh"]
