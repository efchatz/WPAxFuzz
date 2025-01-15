# Use the official Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Set the working directory
WORKDIR /WPAxFuzz

# Install Python and pip
RUN apt-get update && apt-get install -y python3 python3-pip

# Install the Python dependencies
RUN pip3 install scapy gramfuzz requests

# Copy the rest of the application code to the container
COPY . .

# Set the default command to run the script with -h if no arguments are provided
ENTRYPOINT ["python3", "fuzz.py"]
CMD ["-h"]