FROM python:3.11-slim

# Install g++ to compile the C++ cipher
RUN apt-get update && apt-get install -y g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy everything
COPY . .

# Compile the C++ binary for Linux
RUN g++ -O2 -std=c++17 -o cipher cipher.cpp

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 5000

# Run with gunicorn
CMD gunicorn server:app --bind 0.0.0.0:${PORT:-5000}
