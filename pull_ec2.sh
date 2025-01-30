aws ecr get-login-password --region us-west-2 --profile nanites | docker login --username AWS --password-stdin 122610501872.dkr.ecr.us-west-2.amazonaws.com/pcap2
docker pull 122610501872.dkr.ecr.us-west-2.amazonaws.com/pcap2:latest
