#!/bin/sh
exec poetry run uvicorn app:app --host 0.0.0.0 --port "$PORT" --workers "$WORKERS"
