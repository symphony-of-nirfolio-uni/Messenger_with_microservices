# Dockerfile

# Pull base image
FROM python:3.8

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /LoginServer

# Install dependencies
COPY requirements.txt /LoginServer/
RUN pip install -r requirements.txt

COPY . /LoginServer/

