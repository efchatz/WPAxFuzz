FROM python
WORKDIR /WPAxFuzz
COPY . /WPAxFuzz

RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get -y install python3 && \
    apt-get install -y python3-pip && \
    pip install scapy && \
    pip install gramfuzz

CMD ["python3", "fuzz.py"]