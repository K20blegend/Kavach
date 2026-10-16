FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/kavach
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir '.[postgres]' && useradd --create-home kavach && mkdir -p .data && chown -R kavach:kavach /srv/kavach
USER kavach
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=3)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
