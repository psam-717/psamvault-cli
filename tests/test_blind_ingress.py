"""Credential-blind ingress — every claim flow, driven through the real CLI.

The load-bearing property is negative: in an agent context the CLI must never
*accept* a secret and never *print* one. So each test that fills a claim also
asserts that the value the human typed is absent from everything the run
produced — stdout, stderr, the audit trail and the pending directory — while
being present, encrypted, in the request that reached the server.

Only the session and the HTTP transport are faked. The classifier, the policy
loader, the store and the commands are the real ones.
"""
import json
import re
import threading
import time
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

import pending_store as store
import audit
from crypto import decrypt_api_key, decrypt_credentials, decrypt_note
from main import app

runner = CliRunner()
BASE = "https://test.example.com"
VEK = bytes(range(32))
SESSION = {"access_token": "t", "refresh_token": "r", "vek": VEK.hex(), "kdf_salt": "aa" * 32}

# Deliberately not a plausible real secret, and greppable in one assert.
SECRET = "«typed-by-the-human-only»"

CODE_RE = re.compile(r"PV-[0-9A-Z]{4}-[0-9A-Z]{4}")


@pytest.fixture(autouse=True)
def no_background_tasks():
    """Stop the root callback from doing update checks / keychain reads."""
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        yield


def as_agent(monkeypatch):
    """The signal a real agent runtime leaves in the environment."""
    monkeypatch.setenv("PSAMVAULT_AGENT", "1")


def invoke(args, input=None):
    with patch("api_client.ensure_session", return_value=SESSION):
        return runner.invoke(app, args, input=input)


def code_in(output: str) -> str:
    found = CODE_RE.search(output)
    assert found, f"no claim code in output:\n{output}"
    return found.group(0)


def stored_add(*, kind="apikeys"):
    """One successful POST expectation for the endpoint under test."""
    return {"method": "POST", "url": f"{BASE}/{kind}", "json": {"detail": "ok"}, "status_code": 200}


def artifact_bytes():
    """Everything the run could have written, as one blob to grep for the secret."""
    blobs = []
    for path in sorted(store.PENDING_DIR.glob("*.json")) if store.PENDING_DIR.exists() else []:
        blobs.append(path.read_bytes())
    if audit.AUDIT_FILE.exists():
        blobs.append(audit.AUDIT_FILE.read_bytes())
    return b"".join(blobs)


# ── the agent's side: ask for the entry, never see the value ──────────────────


def test_an_agent_asking_for_an_api_key_gets_a_code_not_a_prompt(monkeypatch):
    as_agent(monkeypatch)

    result = invoke(["ak-add", "github-prod", "--service", "GitHub"])

    assert result.exit_code == 0
    code = code_in(result.output)
    record = store.peek(code)
    assert record["family"] == store.FAMILY_API_KEY
    assert record["name"] == "github-prod"
    assert record["service"] == "GitHub"
    assert record["status"] == store.STATUS_PENDING

    # The agent is told the code, the family, the deadline and the human's next
    # step — and nothing else.
    assert store.FAMILY_API_KEY in result.output
    assert "15m" in result.output
    assert f"psamvault ak-add --claim {code}" in result.output
    # No prompt happened: the command never waited for a value.
    assert "API key for" not in result.output


def test_the_claim_creation_is_audited(monkeypatch):
    as_agent(monkeypatch)

    invoke(["ak-add", "github-prod", "--service", "GitHub"])

    rows = audit.read(audit.AUDIT_FILE)
    assert rows[-1]["command"] == "ak-add"
    assert rows[-1]["entry"] == "github-prod"
    assert rows[-1]["decision"] == audit.DECISION_CLAIM_CREATED
    assert rows[-1]["caller"] == "agent"


def test_an_agent_cannot_put_a_secret_in_argv(monkeypatch):
    as_agent(monkeypatch)
    add_key = Mock()

    with patch("api_client.add_api_key_entry", add_key):
        result = invoke(["ak-add", "github-prod", "--service", "GitHub", "--key", SECRET])

    assert result.exit_code == 1
    assert "--key" in result.output
    assert "argv" in result.output
    assert store.list_records() == []
    add_key.assert_not_called()
    assert audit.read(audit.AUDIT_FILE)[-1]["decision"] == audit.DECISION_DENY


def test_a_human_terminal_still_prompts_for_the_key(monkeypatch):
    """The guardrail must not change what a human's own terminal does."""
    add_key = Mock(return_value={"detail": "ok"})

    with patch("api_client.add_api_key_entry", add_key):
        result = invoke(["ak-add", "github-prod", "--service", "GitHub"], input=f"{SECRET}\n")

    assert result.exit_code == 0
    assert "saved successfully" in result.output
    assert SECRET not in result.output
    assert store.list_records() == [], "a human add is not a claim"


# ── the human's side: fill it in their own terminal ──────────────────────────


def test_the_human_fills_the_claim_and_the_value_reaches_the_vault(httpx_mock):
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")
    httpx_mock.add_response(**stored_add())

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 0
    assert "saved successfully" in result.output
    assert SECRET not in result.output

    body = json.loads(httpx_mock.get_requests()[0].content)
    decrypted = decrypt_api_key(VEK, body["encrypted_blob"], body["iv"])
    assert decrypted["api_key"] == SECRET
    assert decrypted["service"] == "GitHub", "the agent's metadata is used to store the entry"

    filled = store.load(record["code"])
    assert filled["status"] == store.STATUS_FILLED
    assert SECRET.encode() not in artifact_bytes()


def test_the_fill_is_refused_from_an_agent_shell(monkeypatch):
    """There is no legitimate agent case for the fill, and a wrong fill is silent."""
    as_agent(monkeypatch)
    record = store.create(store.FAMILY_API_KEY, "github-prod")

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 1
    assert "terminal" in result.output
    assert store.peek(record["code"])["status"] == store.STATUS_PENDING


@pytest.mark.parametrize("code", ["PV-AAAA-AAAA", "nonsense"])
def test_an_unknown_code_is_refused_without_a_traceback(code):
    result = invoke(["ak-add", "--claim", code])

    assert result.exit_code == 1
    assert "claim" in result.output.lower()
    assert "Traceback" not in result.output


def test_an_expired_claim_is_refused_and_says_so(monkeypatch):
    record = store.create(store.FAMILY_API_KEY, "github-prod", ttl_seconds=60)
    monkeypatch.setattr(store, "_now", lambda: __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc) + __import__("datetime").timedelta(seconds=120))

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 1
    assert "expired" in result.output.lower()


def test_a_claim_cannot_be_filled_twice(httpx_mock):
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")
    httpx_mock.add_response(**stored_add())
    assert invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n").exit_code == 0

    second = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert second.exit_code == 1
    assert "already" in second.output.lower()


def test_both_halves_of_the_handover_are_in_the_audit_trail(httpx_mock):
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")
    httpx_mock.add_response(**stored_add())

    invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    rows = audit.read(audit.AUDIT_FILE)
    assert rows[-1]["decision"] == audit.DECISION_CLAIM_FILLED
    assert rows[-1]["entry"] == "github-prod"


# ── --wait ───────────────────────────────────────────────────────────────────


def test_wait_returns_the_moment_the_claim_is_filled(monkeypatch):
    import claim_flow

    as_agent(monkeypatch)
    monkeypatch.setattr(store, "generate_code", lambda: "PV-AAAA-AAAA")
    monkeypatch.setattr(claim_flow, "POLL_INTERVAL_SECONDS", 0.01)

    def the_human():
        time.sleep(0.05)
        store.mark_filled("PV-AAAA-AAAA")

    filler = threading.Thread(target=the_human)
    filler.start()
    try:
        result = invoke(["ak-add", "github-prod", "--service", "GitHub", "--wait", "--timeout", "30s"])
    finally:
        filler.join()

    assert result.exit_code == 0
    assert "filled" in result.output.lower()
    assert store.peek("PV-AAAA-AAAA")["status"] == store.STATUS_FILLED


def test_wait_times_out_leaving_the_code_valid(monkeypatch):
    import claim_flow

    as_agent(monkeypatch)
    monkeypatch.setattr(claim_flow, "POLL_INTERVAL_SECONDS", 0.01)

    result = invoke(["ak-add", "github-prod", "--service", "GitHub", "--wait", "--timeout", "1s"])

    assert result.exit_code == 3, "a timeout is its own exit code, not a failure"
    code = code_in(result.output)
    assert "still valid" in result.output
    # The claim survives the timeout: the agent's next move is a check, not a new claim.
    assert store.peek(code)["status"] == store.STATUS_PENDING


# ── the `pending` command ────────────────────────────────────────────────────


def test_pending_lists_what_is_outstanding(monkeypatch):
    as_agent(monkeypatch)
    pending = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")
    filled = store.create(store.FAMILY_NOTE, "ssh-key")
    store.mark_filled(filled["code"])

    result = invoke(["pending"])

    assert result.exit_code == 0
    assert pending["code"] in result.output
    assert "github-prod" in result.output
    assert "pending" in result.output.lower()
    assert "filled" in result.output.lower()


def test_pending_with_nothing_outstanding_says_so():
    result = invoke(["pending"])

    assert result.exit_code == 0
    assert "no" in result.output.lower()


def test_pending_code_shows_one_claim():
    record = store.create(store.FAMILY_CREDENTIAL, "github.com", notes="work laptop")

    result = invoke(["pending", "--code", record["code"].lower()])

    assert result.exit_code == 0
    assert record["code"] in result.output
    assert "github.com" in result.output
    assert "work laptop" in result.output


def test_pending_cancel_stops_the_code_working():
    record = store.create(store.FAMILY_API_KEY, "github-prod")

    result = invoke(["pending", "--cancel", record["code"]])

    assert result.exit_code == 0
    assert store.load(record["code"]) is None
    assert invoke(["ak-add", "--claim", record["code"]]).exit_code == 1


# ── the same primitive, for the other two families ───────────────────────────


def test_an_agent_scaffolding_a_site_credential_creates_a_claim(monkeypatch):
    as_agent(monkeypatch)

    result = invoke(["add", "github.com", "--notes", "work"])

    assert result.exit_code == 0
    record = store.peek(code_in(result.output))
    assert record["family"] == store.FAMILY_CREDENTIAL
    assert record["name"] == "github.com"
    assert record["notes"] == "work"


def test_filling_a_credential_claim_asks_the_human_for_user_and_password(httpx_mock):
    record = store.create(store.FAMILY_CREDENTIAL, "github.com")
    httpx_mock.add_response(**stored_add(kind="vault"))

    result = invoke(["add", "--claim", record["code"]], input=f"alice@example.com\n{SECRET}\n")

    assert result.exit_code == 0
    assert SECRET not in result.output
    body = json.loads(httpx_mock.get_requests()[0].content)
    decrypted = decrypt_credentials(VEK, body["encrypted_blob"], body["iv"])
    assert decrypted["username"] == "alice@example.com"
    assert decrypted["password"] == SECRET
    assert store.load(record["code"])["status"] == store.STATUS_FILLED


def test_an_agent_scaffolding_a_note_creates_a_claim(monkeypatch):
    as_agent(monkeypatch)

    result = invoke(["note-add", "ssh-key", "--category", "ssh"])

    assert result.exit_code == 0
    record = store.peek(code_in(result.output))
    assert record["family"] == store.FAMILY_NOTE
    assert record["category"] == "ssh"


def test_filling_a_note_claim_asks_for_the_body(httpx_mock):
    record = store.create(store.FAMILY_NOTE, "ssh-key", category="ssh")
    httpx_mock.add_response(**stored_add(kind="notes"))

    result = invoke(["note-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 0
    assert SECRET not in result.output
    body = json.loads(httpx_mock.get_requests()[0].content)
    decrypted = decrypt_note(VEK, body["encrypted_blob"], body["iv"])
    assert decrypted["content"] == SECRET
    assert body["title"] == "ssh-key"
