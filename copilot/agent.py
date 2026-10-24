"""SwarmSentinel as a custom engine agent for Microsoft 365 Copilot and Teams (Microsoft 365 Agents SDK), 2026-09-26.

Run it:  python app.py      (listens on localhost:3978/api/messages)
Test it: Microsoft 365 Agents Playground, see README.md

2026-09-30: status and threats answer with Adaptive Cards, and "alerts on" subscribes a chat to proactive alerts
(alerts.py posts new findings into it).
"""
import os

import logging
from http import HTTPStatus

from microsoft_agents.activity import (
    Activity,
    ActivityTypes,
    AdaptiveCardInvokeResponse,
    Attachment,
    ConversationReference,
)
from microsoft_agents.hosting.aiohttp import CloudAdapter
from microsoft_agents.hosting.core import (
    AgentApplication,
    AgentAuthConfiguration,
    AnonymousTokenProvider,
    ClaimsIdentity,
    ConnectionManager,
    MemoryStorage,
    TurnContext,
    TurnState,
)

import alerts
import approvals
import cards
import replies
import ssai_client

log = logging.getLogger("ssai.agent")
MAX_PENDING_CARDS = 5


def anonymous_connections() -> ConnectionManager:
    """Local testing (Agents Playground) needs no credentials. SDK 1.7 insists on a connection manager (both the adapter
    and AgentApplication take it), so give it one service connection that hands out anonymous tokens. For Teams /
    Copilot this becomes the MSAL connection manager (package microsoft-agents-authentication-msal) configured from the
    Entra app registration."""
    return ConnectionManager(lambda _cfg: AnonymousTokenProvider(), {"SERVICE_CONNECTION": AgentAuthConfiguration()})


def dashboard_url():
    """Optional "Open SwarmSentinel" button on cards. Only useful where people can reach the hub (LAN / VPN)."""
    return os.environ.get("SSAI_DASHBOARD_URL") or None


def card_activity(card: dict) -> Activity:
    return Activity(type=ActivityTypes.message, attachments=[Attachment(content_type=cards.CONTENT_TYPE, content=card)])


def sso_token_source(app, handler):
    """The signed-in person's Entra token for this turn, from the SDK's user authorization (Teams single sign-on via
    the Azure Bot OAuth connection named `handler`), or None when sign-in is not set up / not completed."""
    async def get(context: TurnContext):
        """Fetch the signed-in person's token for this chat turn, or None if there is no sign-in set up or it failed."""
        if not handler:
            return None
        try:
            tr = await app.auth.get_token(context, handler)
        except Exception as exc:                    # noqa: BLE001 (no auth configured yet, or the exchange failed)
            log.warning("no user token for an approval press: %s", type(exc).__name__)
            return None
        return getattr(tr, "token", None) or None
    return get


def build_app(fetch=ssai_client.fetch_brief, connections=None, store=None, fetch_proposals=ssai_client.fetch_proposals,
              decide=ssai_client.decide, user_token=None) -> AgentApplication:
    """Assemble the Copilot/Teams agent: register how it answers help, status, threats, alerts and approval requests, and attach the background poller that sends proactive alerts.
    The parameters let tests swap in fake versions of the hub calls and storage.
    """
    connections = connections or anonymous_connections()
    app = AgentApplication[TurnState](storage=MemoryStorage(), adapter=CloudAdapter(connection_manager=connections),
                                      connection_manager=connections)
    store = store or alerts.Store()
    app_id = os.environ.get("MICROSOFT_APP_ID", "")        # empty in anonymous (Playground) mode

    async def _help(context: TurnContext, _: TurnState):
        await context.send_activity(replies.HELP)

    app.conversation_update("membersAdded")(_help)
    app.message("/help")(_help)

    @app.activity("message")
    async def _on_message(context: TurnContext, _: TurnState):
        """Answer one chat message: work out what the person asked for (help, alerts on/off, pending approvals, threats or status) and reply with text or a card.
        If the hub cannot be reached, say so instead of failing.
        """
        kind, arg = replies.intent(context.activity.text)
        if kind == "help":
            await context.send_activity(replies.HELP)
            return
        if kind == "alerts":
            cid = context.activity.conversation.id
            if arg == "off":
                await context.send_activity(replies.alerts_reply("off", was_on=store.unsubscribe(cid)))
            else:
                ref = context.activity.get_conversation_reference()
                store.subscribe(cid, ref.model_dump(mode="json", by_alias=True, exclude_none=True), arg)
                await context.send_activity(replies.alerts_reply(arg))
            return
        if kind == "pending":
            try:
                data = await fetch_proposals()
            except replies.HubError as exc:
                await context.send_activity(f"I can't reach SwarmSentinel right now ({exc}).")
                return
            proposals = data.get("proposals") or []
            if not proposals:
                await context.send_activity("Nothing is waiting for approval.")
                return
            for p in proposals[:MAX_PENDING_CARDS]:
                await context.send_activity(card_activity(
                    cards.approval_card(p, bool(data.get("approvals_enabled")), dashboard_url())))
            if len(proposals) > MAX_PENDING_CARDS:
                await context.send_activity(f"…and {len(proposals) - MAX_PENDING_CARDS} more in the dashboard.")
            return
        try:
            brief = await fetch(limit=20 if arg else 5)
        except replies.HubError as exc:
            await context.send_activity(f"I can't reach SwarmSentinel right now ({exc}).")
            return
        card = (cards.threats_card(brief, arg, dashboard_url()) if kind == "threats"
                else cards.status_card(brief, dashboard_url()))
        await context.send_activity(card_activity(card))

    async def send(reference: dict, card: dict):
        """Post one card into a stored conversation (proactive message)."""
        ref = ConversationReference.model_validate(reference)

        async def _post(ctx: TurnContext):
            await ctx.send_activity(card_activity(card))

        if app_id:
            await app.adapter.continue_conversation(app_id, ref.get_continuation_activity(), _post)
        else:
            # Anonymous (Playground) mode. SDK 1.7 treats a proactive turn as anonymous only when the identity has NO
            # claims, and continue_conversation("") always adds (empty) app-id claims, so it tries to fetch a real
            # token and fails ("Failed to obtain token for user token client"). An empty identity takes the
            # anonymous path, like the incoming Playground messages do.
            await app.adapter.continue_conversation_with_claims(ClaimsIdentity({}, authentication_type="anonymous"),
                                                                ref.get_continuation_activity(), _post)

    # Approve / Reject on a proposal card (Action.Execute). With SSAI_SSO_HANDLER set (the Azure Bot OAuth connection,
    # configured with the Microsoft 365 tenant), the SDK signs the person in first; the hub then checks their token.
    sso = os.environ.get("SSAI_SSO_HANDLER", "").strip()
    token_for = user_token or sso_token_source(app, sso)
    auth_handlers = [sso] if sso else None

    def _decision(action):
        async def handler(context: TurnContext, _: TurnState, data):
            card = await approvals.handle(action, data, await token_for(context), decide, dashboard_url())
            return AdaptiveCardInvokeResponse(status_code=HTTPStatus.OK, type=cards.CONTENT_TYPE, value=card)
        return handler

    app.adaptive_card.action_execute(cards.APPROVE_VERB, auth_handlers=auth_handlers)(_decision("approve"))
    app.adaptive_card.action_execute(cards.REJECT_VERB, auth_handlers=auth_handlers)(_decision("reject"))

    app.ssai_poller = alerts.Poller(store, fetch, send, dashboard_url(), fetch_proposals=fetch_proposals)
    return app
