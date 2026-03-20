FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system recon && adduser --system --ingroup recon recon

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output && chown -R recon:recon /app

USER recon

VOLUME ["/app/output"]

ENTRYPOINT ["python", "main.py"]
