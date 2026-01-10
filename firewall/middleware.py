# security/firewall/middleware.py

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from security.config import FirewallConfig
from security.firewall.utils.utils import get_client_ip
from security.firewall.rate_limit import hit_rate_limit
from security.firewall.blacklist import is_blocked
from security.firewall.strike_engine import escalate_if_needed
from security.firewall.exceptions import FirewallExceptions

from security.policies.cache import resolve_policy_cached
from security.policies.definitions import POLICIES

from utilities.common.common_utility import debug_print

class FirewallMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        # 1. Exemptions (docs, health checks, etc.)
        if FirewallExceptions.is_exempt(path, method):
            debug_print(f"[FIREWALL] EXEMPT {method} {path}", color="cyan")
            return await call_next(request)

        # 2. Resolve policy (JIT cached)
        policy = resolve_policy_cached(path)
        policy_def = POLICIES[policy]

        debug_print(f"[FIREWALL] {method} {path} -> policy={policy}", color="cyan")

        # 3. Identify client
        ip = get_client_ip(request)

        # 4. Fingerprint (only if required by policy)
        fingerprint = None
        if policy_def.fingerprint_required:
            fingerprint = request.headers.get(FirewallConfig.FINGERPRINT_HEADER)

        # 5. Check DB blocks (temporary + permanent)
        blocked, reason = await is_blocked(ip=ip, fingerprint=fingerprint)
        if blocked:
            debug_print(f"[FIREWALL] BLOCKED {ip} reason={reason}", color="red")
            return JSONResponse(
                {
                    "error": "Access blocked",
                    "reason": reason or "Security policy enforcement",
                },
                status_code=403,
            )

        # 6. Build rate-limit identity key
        if policy_def.escalation_scope == "ROUTE":
            rate_key = f"{policy}:ROUTE:{path}:{ip}"
        elif policy_def.escalation_scope == "IP_FINGERPRINT":
            rate_key = f"{policy}:IP_FP:{ip}:{fingerprint or 'no-fp'}"
        else:  # IP or GLOBAL
            rate_key = f"{policy}:IP:{ip}"

        # 7. Apply rate limit
        allowed = await hit_rate_limit(
            key=rate_key,
            limit=policy_def.requests,
            window=policy_def.window.total_seconds(),
        )

        if not allowed:
            debug_print(f"[FIREWALL] RATE LIMIT HIT {rate_key}", color="yellow")

            promoted, escalation_msg = await escalate_if_needed(
                ip=ip,
                policy_name=policy.value,
                scope=policy_def.escalation_scope,
                window=policy_def.window.total_seconds(),
                threshold=policy_def.escalate_after,
                path=path,
                fingerprint=fingerprint,
                promote_to_permanent=policy_def.global_block,
            )

            if promoted and policy_def.global_block:
                return JSONResponse(
                    {
                        "error": "Permanently blocked",
                        "reason": escalation_msg,
                    },
                    status_code=403,
                )

            return JSONResponse(
                {
                    "error": "Too many requests",
                    "message": "You are temporarily blocked. Continued abuse may result in permanent ban.",
                },
                status_code=429,
            )

        # 8. Allowed -> forward to API
        return await call_next(request)
