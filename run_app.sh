#!/bin/bash

apt update && apt -y upgrade

# Older version of Java allows RCE vulnerability
apt -y install openjdk-11-jdk

# Nice to have for reverse shell payload
apt -y install ncat

git clone https://github.com/34006133/Vuln-Text4Shell-App
cd Vuln-Text4Shell-App
cd vulnerable

# Build system
./mvnw clean install
./mvnw clean package

java -jar target/vulnerable-0.0.1-SNAPSHOT.jar
