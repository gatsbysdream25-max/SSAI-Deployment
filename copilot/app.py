"""Start the SwarmSentinel agent: python app.py  (reads copilot/.env, listens on HOST:PORT, default localhost:3978)."""
import asyncio
import contextlib
import logging
import os
import sys

from aiohttp.web import Application, Request, Response, run_app
from dotenv import load_dotenv
from microsoft_agents.hosting.aiohttp import jwt_authorization_middleware, start_agent_process
from microsoft_agents.hosting.core import AgentAuthConfiguration

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from agent import build_app  # noqa: E402  (after load_dotenv: the client reads its settings at call time anyway)

LOCAL_ONLY = ("localhost", "127.0.0.1", "::1")


def main():
    """Start the agent's web server, refusing to run on a network address while in anonymous (no sign-in) mode, and start
    the background alert poller."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    host =os.environ.get("HOST", "localhost")
    if host not in LOCAL_ONLY:
        # Anonymous mode (no Entra app yet) accepts any caller. That is fine for the Agents Playground on this machine,
        # never on a network address: anyone who can reach it could read the brief without a credential.
        sys.exit(f"Refusing to start: anonymous mode may only listen on {', '.join(LOCAL_ONLY)} (HOST={host}). "
                 "Set up Entra / Azure Bot authentication before exposing the agent.")
    agent_app = build_app()

    async def entry_point(req: Request) -> Response:
        return await start_agent_process(req, req.app["agent_app"], req.app["adapter"])

    async def alive(_: Request) -> Response:
        return Response(status=200)

    web = Application(middlewares=[jwt_authorization_middleware])
    web.router.add_post("/api/messages", entry_point)
    web.router.add_get("/api/messages", alive)
    # SDK 1.7 needs an explicit configuration; anonymous_allowed is what the Agents Playground uses locally.
    web["agent_configuration"] = AgentAuthConfiguration(anonymous_allowed=True)
    web["agent_app"] = agent_app
    web["adapter"] = agent_app.adapter

    # Proactive alerts (alerts.py): one background poller for the life of the server.
    async def start_alerts(app):
        interval = max(15, int(os.environ.get("SSAI_ALERT_POLL_SECONDS", "60")))
        app["alerts"] = asyncio.create_task(agent_app.ssai_poller.run(interval))

    async def stop_alerts(app):
        app["alerts"].cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await app["alerts"]

    web.on_startup.append(start_alerts)
    web.on_cleanup.append(stop_alerts)
    run_app(web, host=host, port=int(os.environ.get("PORT", 3978)))


if __name__ == "__main__":
    main()
