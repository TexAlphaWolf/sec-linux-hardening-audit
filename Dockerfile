FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

# Audits a directory tree mounted read-only at /host (the machine, or an exported image):
#   docker run --rm -v /:/host:ro hardaudit audit --root /host
# It runs as root because reading /etc/shadow needs it; with a read-only mount it cannot change
# anything. `fix --apply` needs a read-write mount and is meant for a machine you own.
ENTRYPOINT ["hardaudit"]
CMD ["--help"]
