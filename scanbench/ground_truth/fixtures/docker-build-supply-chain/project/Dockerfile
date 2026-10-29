FROM python:3.13

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1

ADD https://downloads.example.com/tool /usr/local/bin/tool
RUN chmod +x /usr/local/bin/tool
RUN pip install requests flask

COPY . /app
HEALTHCHECK CMD python -c "import socket; socket.create_connection(('127.0.0.1', 8080), 1)"
CMD ["python", "-c", "print('ready')"]
