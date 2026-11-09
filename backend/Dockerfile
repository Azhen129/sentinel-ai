FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip setuptools && python -m pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 sentinel
COPY backend ./backend
COPY detection ./detection
COPY models ./models
RUN mkdir -p /app/data && chown -R sentinel:sentinel /app
USER sentinel
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
