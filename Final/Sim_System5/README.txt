Each folder is a container. 
For building each container into an image and then running that image each folder has a Commands.txt file.
The first two lines of any Commands.txt file build and run the Docker container.

Some Commands.txt might give some extra information about the container, how it works or what could be changed/modified after the two build-run commands. 

In general you can check if a container is running by checking the logs but if there could be some container that doesn't print anything on the logs when running. 

Some attackers act very slowly (Leaving for over 20 minutes won't impact severely the performance of the server), some attackers act extremely quickly (If you leave them for more than 2 minutes your PC performance might extremely drop), and some attackers can be easily modified to be stronger or weaker (Commands.txt might give info into doing it, sometimes Commands.txt doesn't give that information but it could still be done)