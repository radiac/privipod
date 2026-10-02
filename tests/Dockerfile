FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

COPY . .

RUN pip install uv && uv sync --group dev
RUN uv run playwright install chromium

# End-to-end tests start their own servers
CMD ["uv", "run", "pytest", "tests/", "-v", "--tb=short"]
