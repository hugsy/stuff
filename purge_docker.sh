#!/bin/bash


set -e

# stop all containers
docker container stop $(docker container ls –aq)

# remove stopped containers
docker container rm $(docker container ls –aq)
docker system prune –af ––volumes

# remove all images
docker image rm $(docker image ls -aq)

exit 0

