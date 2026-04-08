.PHONY: up down up-full down-full migrate seed test test-unit lint format api dashboard logs worker beat enrich-epss enrich-kev enrich-nvd enrich-all

up:
	docker compose up -d

down:
	docker compose down

up-full:
	docker compose -f docker-compose.yml -f docker-compose.greenbone.yml up -d

down-full:
	docker compose -f docker-compose.yml -f docker-compose.greenbone.yml down

worker:
	uv run celery -A src.workers.celery_app worker --loglevel=info -Q scans,celery

beat:
	uv run celery -A src.workers.celery_app beat --loglevel=info

migrate:
	uv run alembic upgrade head

seed:
	uv run python scripts/seed_db.py

test:
	uv run pytest tests/ -v

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
