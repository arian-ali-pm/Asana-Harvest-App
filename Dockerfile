FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY asanaharvestdashboard.py .
COPY static ./static

# Create data directory for SQLite
RUN mkdir -p /data

# Set environment variables
ENV HOST=0.0.0.0
ENV PORT=8080
ENV DB_PATH=/data/dashboard.db

EXPOSE 8080

CMD ["python", "asanaharvestdashboard.py"]
