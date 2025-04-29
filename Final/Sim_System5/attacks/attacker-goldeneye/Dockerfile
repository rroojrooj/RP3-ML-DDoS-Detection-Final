# GOLDENEYE ATTACKER DOCKER FILE
FROM kalilinux/kali-rolling

# Install dependencies
RUN apt-get update && apt-get install -y git python3 python3-pip

# Clone GoldenEye from GitHub
RUN git clone https://github.com/jseidl/GoldenEye.git /goldeneye

# Inject delay into goldeneye.py using sed
# RUN sed -i '/conn_req.request.*headers)/a \                    time.sleep(1.0)' /goldeneye/goldeneye.py

WORKDIR /goldeneye

# Run the attack script
CMD ["python3", "goldeneye.py", "http://localhost", "-w", "1", "-s", "1"]
