FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt
COPY backend /app/backend
COPY scanner /app/scanner
COPY examples /app/examples
ENV PYTHONPATH=/app
EXPOSE 8000
