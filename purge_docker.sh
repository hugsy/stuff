#!/bin/bash

set -e
set -x

# stop all containers
running_containers="$(docker container ls -a -q)"
test "${running_containers}" != "" && docker container stop $running_containers

# remove stopped containers
containers="$(docker container ls -a -q)"
test "${containers}" != "" && docker container rm $containers

# prunes all the volumes
docker system prune -a -f --volumes

# remove all images
images="$(docker image ls -a -q)"
test "${images}" != "" && docker image rm $images

exit 0

