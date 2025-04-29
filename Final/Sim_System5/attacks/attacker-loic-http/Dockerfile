FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y hping3

# Copy and set permissions for traffic script
COPY attack_flood.sh /attack_flood.sh
RUN chmod +x /attack_flood.sh

# CMD ["tail", "-f", "/dev/null"]
CMD ["/bin/bash", "/attack_flood.sh"]