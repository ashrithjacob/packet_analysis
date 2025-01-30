docker build -t app2:latest -f Dockerfile .
aws ecr create-repository --repository-name pcap2 --profile nanites
docker tag app2:latest 122610501872.dkr.ecr.us-west-2.amazonaws.com/pcap2:latest
aws ecr get-login-password --region us-west-2 --profile nanites | docker login --username AWS --password-stdin 122610501872.dkr.ecr.us-west-2.amazonaws.com/pcap2
docker push 122610501872.dkr.ecr.us-west-2.amazonaws.com/pcap2
