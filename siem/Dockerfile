FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY engine ./engine
COPY rules ./rules
EXPOSE 8001
CMD ["uvicorn", "engine.api:app", "--host", "0.0.0.0", "--port", "8001"]
