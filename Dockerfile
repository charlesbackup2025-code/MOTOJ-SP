FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app/motoja-sp
RUN mkdir -p /app/data
ENV PORT=8080
ENV STORAGE=sqlite
ENV SQLITE_FILE=/app/data/motoja.sqlite3
ENV UPLOAD_DIR=/app/data/uploads
EXPOSE 8080
CMD ["python3", "/app/motoja-sp/server.py"]
