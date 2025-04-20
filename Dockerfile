# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file first to leverage Docker cache
COPY requirements.txt ./

# Install any needed packages specified in requirements.txt
# --no-cache-dir reduces image size, --trusted-host is sometimes needed in firewalled environments
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the working directory
COPY *.py ./

# Set default values to empty strings. These will be overridden at runtime.
ENV VIRUSTOTAL_API_KEY=""
ENV ISMALICIOUS_API_KEY=""
ENV ISMALICIOUS_API_SECRET=""

# Expose the standard DNS ports the application listens on
EXPOSE 53/udp
EXPOSE 53/tcp

# Set standard output and standard error streams to no buffer mode, preventing delays in output.
ENV PYTHONUNBUFFERED=1

# Used to specify the command to run the script
ENTRYPOINT ["python", "main.py"]

# These will be used if no arguments are provided on 'docker run'
CMD ["-v"]
