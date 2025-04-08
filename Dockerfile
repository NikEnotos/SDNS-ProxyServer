# Dockerfile

# Use an official Python runtime as a parent image
# Using a slim variant reduces the image size
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file first to leverage Docker cache
COPY requirements.txt ./

# Install any needed packages specified in requirements.txt
# --no-cache-dir reduces image size, --trusted-host is sometimes needed in firewalled environments
RUN pip install --no-cache-dir --trusted-host pypi.python.org -r requirements.txt

# Copy the rest of the application code into the working directory
COPY *.py ./

# --- Environment Variables for API Keys (Best Practice) ---
# Set default values to empty strings. These will be overridden at runtime.
ENV VIRUSTOTAL_API_KEY=""
ENV ISMALICIOUS_API_KEY=""
ENV ISMALICIOUS_API_SECRET=""

# --- Expose Ports ---
# Expose the standard DNS ports the application listens on
EXPOSE 53/udp
EXPOSE 53/tcp

# Use the exec form for ENTRYPOINT
ENTRYPOINT ["python", "main.py"]

# --- Define default arguments for the ENTRYPOINT ---
# These will be used if no arguments are provided on 'docker run'
# Use the exec form for CMD as well
CMD ["-vv"]