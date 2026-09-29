"""Event API between the detection engine and the Netra desktop app.

This serves no web page. It exists because the engine usually runs inside the
Docker lab while the desktop app runs on the host, so events need a channel
across the container boundary.

  WS   /ws                  on connect: status, recent alerts/actions and blocks;
                            then every engine event as JSON
  GET  /api/status          engine and model status
  GET  /api/alerts          recent alerts and actions
  GET  /api/blocks          active blocks and quarantines
  POST /api/block/{ip}      manual block by the operator (timed, like automatic blocks)
  POST /api/unblock-all     remove every Netra firewall rule
  POST /api/unblock/{ip}    remove the rule for one address
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

log = logging.getLogger(__name__)


def create_app(engine) -> FastAPI:
    app = FastAPI(title="Netra event API", docs_url=None, redoc_url=None)

    @app.get("/api/status")
    def status():
        return engine.status()

    @app.get("/api/alerts")
    def alerts():
        return list(engine.bus.history)

    @app.get("/api/blocks")
    def blocks():
        return engine.responder.active()

    @app.post("/api/unblock-all")
    def unblock_all():
        rec = engine.responder.unblock_all()
        engine.bus.publish({"type": "blocks", "blocks": engine.responder.active()})
        return rec

    @app.post("/api/block/{ip}")
    def block(ip: str):
        import ipaddress

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"action": "invalid", "ip": ip}
        rec = engine.responder.block(ip, "manual block by operator")
        engine.bus.publish({"type": "blocks", "blocks": engine.responder.active()})
        return rec

    @app.post("/api/unblock/{ip}")
    def unblock(ip: str):
        rec = engine.responder.unblock(ip, "manual")
        engine.bus.publish({"type": "blocks", "blocks": engine.responder.active()})
        return rec or {"action": "none", "ip": ip}

    @app.websocket("/ws")
    async def ws(socket: WebSocket):
        await socket.accept()
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=5000)

        def push(event: dict) -> None:
            def put():
                if not q.full():
                    q.put_nowait(event)
            loop.call_soon_threadsafe(put)

        unsubscribe = engine.bus.subscribe(push)
        try:
            await socket.send_text(json.dumps(engine.status()))
            await socket.send_text(json.dumps({"type": "history", "events": list(engine.bus.history)}))
            await socket.send_text(json.dumps({"type": "blocks", "blocks": engine.responder.active()}))
            while True:
                event = await q.get()
                await socket.send_text(json.dumps(event, default=str))
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            unsubscribe()

    return app


def serve_in_background(engine, host: str, port: int) -> threading.Thread:
    """Run the API with uvicorn in a daemon thread."""
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(create_app(engine), host=host, port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, name="api", daemon=True)
    thread.start()
    log.info("event API listening on %s:%d", host, port)
    return thread
