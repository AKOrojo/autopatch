import redis.asyncio as aioredis

redis_client: aioredis.Redis | None = None


def init_redis(redis_url: str):
    global redis_client
    redis_client = aioredis.from_url(redis_url, decode_responses=True)


async def close_redis():
    global redis_client
    if redis_client:
        await redis_client.close()
