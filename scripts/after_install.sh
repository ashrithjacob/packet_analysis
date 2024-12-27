#!/bin/bash
echo 'run after_install.sh: ' >> /home/ubuntu/packet_analysis/deploy.log

echo 'cd /home/ubuntu/packet_analysis' >> /home/ubuntu/packet_analysis/deploy.log
cd /home/ubuntu/packet_analysis >> /home/ubuntu/packet_analysis/deploy.log

echo 'closing docker containers' >> /home/ubuntu/packet_analysis/deploy.log
docker compose down >> /home/ubuntu/packet_analysis/deploy.log