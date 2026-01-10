from sqlalchemy import select
from database.security.session import get_session
from database.security.models import PermanentBlacklist

async def is_permanently_blocked(ip: str) -> bool:
    async with get_session() as session:
        res = await session.execute(
            select(PermanentBlacklist).where(PermanentBlacklist.ip_address == ip)
        )
        return res.scalar_one_or_none() is not None
