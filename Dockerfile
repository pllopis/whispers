FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies (pin if you prefer)
RUN pip install --no-cache-dir \
    fastapi==0.115.0 \
    uvicorn[standard]==0.30.6 \
    authlib==1.3.1 \
    python-multipart==0.0.9 \
    httpx==0.27.2 \
    Jinja2==3.1.4 \
    itsdangerous==2.2.0 \
    cryptography==43.0.1 \
    SQLAlchemy==2.0.34 \
    psycopg2-binary==2.9.9

# Copy the application source
COPY app /app/app

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]