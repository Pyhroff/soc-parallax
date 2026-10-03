FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY app ./app
COPY db ./db
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir .

RUN useradd --system --no-create-home --uid 10001 parallax
USER parallax

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
