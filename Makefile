.PHONY: up down up-full down-full migrate migrate-test seed test test-unit test-live test-live-llm test-live-terraform lint format api dashboard logs worker worker-agents beat enrich-epss enrich-kev enrich-nvd enrich-all vllm vllm-remote vllm-logs vault vault-init vault-logs vault-status

up:
	docker compose up -d --scale vllm=0

down:
	docker compose down

up-full:
	docker compose -f docker-compose.yml -f docker-compose.greenbone.yml up -d --scale vllm=0

down-full:
	docker compose -f docker-compose.yml -f docker-compose.greenbone.yml down

worker:
	uv run celery -A src.workers.celery_app worker --loglevel=info -Q scans,celery

worker-agents:
	uv run celery -A src.workers.celery_app worker --loglevel=info -Q agents

beat:
	uv run celery -A src.workers.celery_app beat --loglevel=info

migrate:
	uv run alembic upgrade head

migrate-test:
	docker compose exec postgres psql -U autopatch -tc "SELECT 1 FROM pg_database WHERE datname = 'autopatch_test'" | grep -q 1 || docker compose exec postgres psql -U autopatch -c "CREATE DATABASE autopatch_test"
	DATABASE_URL=postgresql+asyncpg://autopatch:autopatch_dev@localhost:5432/autopatch_test uv run alembic upgrade head

seed:
	uv run python scripts/seed_db.py

test:
	uv run pytest tests/ -v -m "not live_llm and not live_terraform"

test-live:
	uv run pytest tests/ -v -m "live_llm or live_terraform"

test-live-llm:
	uv run pytest tests/ -v -m live_llm

test-live-terraform:
	uv run pytest tests/ -v -m live_terraform

test-unit:
	uv run pytest tests/unit/ -v

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/

api:
	uv run uvicorn src.api.main:app --reload --port 8000

dashboard:
	cd dashboard && bun run dev

logs:
	docker compose logs -f

enrich-epss:
	uv run python scripts/import_epss.py

enrich-kev:
	uv run python scripts/import_kev.py

enrich-nvd:
	uv run python scripts/import_cve_feed.py

enrich-all:
	uv run python scripts/import_epss.py && uv run python scripts/import_kev.py && uv run python scripts/import_cve_feed.py

vllm:
	docker compose up -d vllm

vllm-remote:
	ssh resbears@10.100.201.26 "docker start vllm 2>/dev/null || docker run -d --name vllm --gpus all --shm-size 16g -p 8001:8000 -v ~/.cache/huggingface:/root/.cache/huggingface vllm/vllm-openai:latest --model Qwen/Qwen3-30B-A3B --tensor-parallel-size 2 --max-model-len 8192"

vllm-logs:
	docker compose logs -f vllm

vault:
	docker compose up -d vault

vault-init:
	docker compose exec vault sh /vault/init-vault.sh

vault-logs:
	docker compose logs -f vault

vault-status:
	docker compose exec vault vault status
