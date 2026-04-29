FROM python:3.11-slim

WORKDIR /app

# Install iptables
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all detector files
COPY . .

CMD ["python", "main.py"]
