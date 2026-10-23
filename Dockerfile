FROM python:3.12-slim

WORKDIR /app

# connection to pypi was unstable, so wait longer and retry more
ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_RETRIES=10

RUN pip install --no-cache-dir flask==3.1.3 requests==2.34.2 PyJWT==2.15.1 gunicorn==23.0.0

COPY app.py .

EXPOSE 80

CMD ["gunicorn", "--bind", "0.0.0.0:80", "--workers", "2", "--timeout", "60", "app:app"]
