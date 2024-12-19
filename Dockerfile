FROM ubuntu:latest

ARG DEBIAN_FRONTEND=noninteractive

RUN echo "==> Upgrading apk and installing system utilities ...." \
 && apt -y update \
 && apt-get install -y wget \
 && apt-get -y install sudo

RUN echo "==> Installing Python3 and pip ...." \  
 && apt-get install python3 -y \
 && apt install python3-pip -y

RUN echo "==> Install dos2unix..." \
  && sudo apt-get install dos2unix -y 

RUN echo "==> Install pip packages..." \
    && pip install --break-system-packages -U --quiet pandas==2.2.3 \
    && pip install --break-system-packages -U --quiet numpy==1.26.4 \
    && pip install --break-system-packages -U --quiet streamlit==1.40.2 \
    && pip install --break-system-packages -U --quiet boto3==1.35.69 \
    && pip install --break-system-packages -U --quiet botocore==1.35.69 \
    && pip install --break-system-packages -U --quiet anthropic==0.40.0 \
    && pip install --break-system-packages -U --quiet langchain-anthropic==0.3.0 \
    && pip install --break-system-packages -U --quiet langchain-aws==0.2.7 \
    && pip install --break-system-packages -U --quiet python-dotenv==1.0.1

RUN echo "==> Install more pip packages..." \
    && pip install --break-system-packages -U --quiet tabulate==0.9.0 \
    && pip install --break-system-packages -U --quiet groq==0.13.0\
    && pip install --break-system-packages -U --quiet openai==1.57.2\
    && pip install --break-system-packages -U --quiet mac-vendor-lookup==0.1.12


# Install tshark
RUN apt-get update && apt-get install -y tshark

RUN echo "==> Adding pyshark ..." \
  && pip install --break-system-packages pyshark

WORKDIR /packet_analysis
COPY ./temp ./temp
COPY ./images ./images
COPY ./src ./src
COPY .env .env

EXPOSE 8501

ENTRYPOINT ["streamlit", "run", "src/packet_tag.py", "--server.port=8501", "--server.address=0.0.0.0"]
