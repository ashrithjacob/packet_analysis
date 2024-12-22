#!/bin/bash

echo 'run application_start.sh: ' >>  /home/ubuntu/packet_analysis/deploy.log
cd /home/ubuntu/packet_analysis >> /home/ubuntu/packet_analysis/deploy.log
# nodejs-app is the same name as stored in pm2 process
echo 'start docker containers' >> /home/ubuntu/packet_analysis/deploy.log
docker compose up  >> /home/ubuntu/packet_analysis/deploy.log