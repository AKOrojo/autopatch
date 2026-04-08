.PHONY: up down migrate seed test lint format api dashboard logs

up:
	docker compose up -d

down:
	docker compose down

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
