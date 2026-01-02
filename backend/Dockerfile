FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for nmap and network scanning
RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    arp-scan \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]


