FROM python:3.12-slim
RUN pip install uv
WORKDIR /app
COPY privipod.py pyproject.toml ./
EXPOSE 8000
ENTRYPOINT ["uv", "run", "privipod.py"]
