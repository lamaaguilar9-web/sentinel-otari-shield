FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY otari_shield ./otari_shield
COPY tests ./tests

EXPOSE 8090
CMD ["uvicorn", "otari_shield.api:app", "--host", "0.0.0.0", "--port", "8090"]
