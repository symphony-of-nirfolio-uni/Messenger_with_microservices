# Dockerfile

# Pull base image
FROM python:3.8

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /MainServer

# Install dependencies
COPY requirements.txt /MainServer/
RUN pip install -r requirements.txt

COPY . /MainServer/

