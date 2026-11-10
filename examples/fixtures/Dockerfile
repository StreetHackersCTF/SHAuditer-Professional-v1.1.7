FROM python:3.12-slim
RUN useradd -r -u 10001 service
WORKDIR /app
COPY . /app
USER service
CMD ["python", "-m", "http.server", "8080"]
