#!/bin/bash

#Retrieve the host IP
IP=$(hostname -I | cut -d "." -f 1,2,3,4 | cut -d " " -f 1)
if [ -z "$IP" ]; then
  echo "Could not retrieve IP address"
  exit 1
fi
echo "IP Address is $IP"

#Retrieve the interface of the IP
INTERFACE=$(ip -o -4 addr show | awk -v ip="$IP" '$4 ~ ip {print $2}')
if [ -z "$INTERFACE" ]; then
  echo "Could not retrieve Interface of the IP Address $IP"
  exit 1
fi
echo "Interface is $INTERFACE"

# Calculate the /28 subnet
IFS='.' read -r -a OCTETS <<< "$IP"
SUBNET="${OCTETS[0]}.${OCTETS[1]}.${OCTETS[2]}.0/28"

# Run fping on the /28 subnet
fping -a -g $SUBNET

# Run nmap -sP on the /28 subnet to fulfill the ARP table
nmap -sP $SUBNET

if [[ $INTERFACE == *mon ]]; then
    echo "Interface $INTERFACE is already in monitoring mode. airmon-ng won't start."
    echo "Network Scanning completed."
    exit 2
fi
# Use airmon-ng to set the interface in monitoring mode
airmon-ng start $INTERFACE

echo "Network Scanning completed."
