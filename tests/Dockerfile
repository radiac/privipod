FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

COPY . .

RUN pip install uv && uv sync --group dev
RUN uv run playwright install chromium

# Start the server in the background, then run tests
CMD ["sh", "-c", \
    "uv run privipod.py 8765 --user=testuser --pass=testpass & \
     sleep 3 && \
     uv run pytest tests/ -v --tb=short"]
