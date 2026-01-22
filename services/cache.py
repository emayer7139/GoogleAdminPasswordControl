from cachetools import TTLCache

admin_api_cache = TTLCache(maxsize=100, ttl=300)
classroom_roster_cache = TTLCache(maxsize=100, ttl=300)
