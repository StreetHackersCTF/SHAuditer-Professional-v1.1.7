from __future__ import annotations
import asyncio
from dataclasses import asdict
import json


class ModuleScheduler:
    def __init__(self, max_parallel: int = 3):
        self.max_parallel = max(1, int(max_parallel))

    async def run(self, modules, context):
        semaphore = asyncio.Semaphore(self.max_parallel)

        async def one(module):
            if not module.available():
                result = __import__("shauditer.integrations.base", fromlist=["ModuleResult"]).ModuleResult(
                    module.name, "UNAVAILABLE", metadata={"executable": module.executable}
                )
                context.db.add_module_run(context.audit_id, module.name, result.status, metadata=result.metadata)
                context.events.emit(__import__("shauditer.core.events", fromlist=["AuditEvent"]).AuditEvent(
                    context.audit_id, "MODULE_UNAVAILABLE", {"module": module.name, **result.metadata}
                ))
                return result
            async with semaphore:
                context.events.emit(__import__("shauditer.core.events", fromlist=["AuditEvent"]).AuditEvent(
                    context.audit_id, "MODULE_STARTED", {"module": module.name}
                ))
                try:
                    result = await module.run(context)
                except Exception as exc:  # scanner failure must not kill the audit
                    result = __import__("shauditer.integrations.base", fromlist=["ModuleResult"]).ModuleResult(
                        module.name, "FAILED", metadata={"error": f"{type(exc).__name__}: {exc}"}
                    )
                context.db.add_module_run(
                    context.audit_id, module.name, result.status,
                    command=result.metadata.get("command", "").split() if result.metadata.get("command") else [],
                    exit_code=result.metadata.get("exit_code"), metadata=result.metadata,
                )
                context.events.emit(__import__("shauditer.core.events", fromlist=["AuditEvent"]).AuditEvent(
                    context.audit_id, "MODULE_FINISHED", {"module": module.name, "status": result.status,
                                                          "assets": len(result.assets), "services": len(result.services),
                                                          "technologies": len(result.technologies)}
                ))
                return result

        return await asyncio.gather(*(one(m) for m in modules))
