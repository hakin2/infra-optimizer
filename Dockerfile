FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY infra_optimizer/ infra_optimizer/

CMD ["python", "-m", "infra_optimizer.processing.ecs_task"]
