# Use Node.js LTS
FROM node:18-slim

# Install system dependencies for Nmap, WhatWeb, and Nuclei
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    git \
    unzip \
    whatweb \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN curl -L https://github.com/projectdiscovery/nuclei/releases/download/v3.2.1/nuclei_3.2.1_linux_amd64.zip -o nuclei.zip && \
    unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.zip

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

ENV NODE_ENV=production
ENV PORT=3001

EXPOSE 3001

CMD ["npm", "start"]
