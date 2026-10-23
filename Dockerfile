ARG PYTHON_BASE=python:3.12-slim
FROM ${PYTHON_BASE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock requirements-agent.lock requirements-semantic.lock pyproject.toml alembic.ini ./
RUN pip install --no-cache-dir -r requirements.lock -r requirements-agent.lock -r requirements-semantic.lock
COPY src ./src
COPY migrations ./migrations
COPY config ./config
RUN pip install --no-cache-dir --no-deps . \
    && useradd --uid 10001 --create-home app \
    && mkdir -p /app/data/raw \
    && chown -R app:app /app/data
USER app
EXPOSE 8000
CMD ["sh", "-c", "python -m zhidu init-db && python -m zhidu serve --host 0.0.0.0"]
