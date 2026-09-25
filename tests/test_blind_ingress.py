"""Credential-blind ingress, driven through the real CLI.

The feature is one handoff: an agent that must not hold a secret asks for the
entry to exist, prints one command, and the human types the value in their own
terminal. The load-bearing properties are negative — the CLI must never accept a
secret from an agent, and never print one — so the value a human typed is
asserted ABSENT from every artifact a run produces: stdout, the audit trail and
the claim file.

The review's done-when list is checked here literally: the agent path prints a
claim, the fill spends the code only after a successful store, both refusals are
audited, `pending` lists and cancels, and the removed flags are gone from
`--help`.
"""
import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import audit
import claim_flow
import pending_store as store
from crypto import decrypt_api_key, decrypt_credentials, decrypt_note
from errors import IngressBlockedError
from main import app

runner = CliRunner()
BASE = "https://test.example.com"
VEK = bytes(range(32))
SESSION = {"access_token": "t", "refresh_token": "r", "vek": VEK.hex(), "kdf_salt": "aa" * 32}
SECRET = "«what-the-human-typed»"

CSRF = "--claim"


@pytest.fixture(autouse=True)
def no_background_tasks():
    with patch("main.start_update_check"), \
         patch("main.check_and_show_upgrade_notice"), \
         patch("main.print_update_notice"):
        yield


def as_agent(monkeypatch):
    monkeypatch.setenv("PSAMVAULT_AGENT", "1")


def invoke(args, input=None):
    with patch("api_client.ensure_session", return_value=SESSION):
        return runner.invoke(app, args, input=input)


def rows():
    """The audit trail this test run wrote."""
    if not audit.AUDIT_FILE.exists():
        return []
    return [
        json.loads(line)
        for line in audit.AUDIT_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def code_in(output):
    """The claim code a command printed."""
    for token in output.replace("-", "-").split():
        if token.startswith("PV-") and len(token) == 12:
            return token
    raise AssertionError(f"no claim code in output:\n{output}")


# ── the agent's half ─────────────────────────────────────────────────────────


def test_an_agent_asking_for_a_key_gets_a_claim_and_no_prompt(monkeypatch):
    as_agent(monkeypatch)

    result = invoke(["ak-add", "github-prod", "--service", "GitHub"])

    assert result.exit_code == 0, result.output
    assert "Traceback" not in result.output
    code = code_in(result.output)
    assert f"psamvault ak-add --claim {code}" in result.output

    record = store.peek(code)
    assert record["name"] == "github-prod"
    assert record["service"] == "GitHub"
    assert record["family"] == store.FAMILY_API_KEY


def test_the_same_shape_for_a_credential_and_a_note(monkeypatch):
    as_agent(monkeypatch)

    credential = invoke(["add", "github.com", "--login-url", "https://github.com/login"])
    note = invoke(["note-add", "ssh-key", "--category", "ssh"])

    assert credential.exit_code == 0 and note.exit_code == 0
    credential_code, note_code = code_in(credential.output), code_in(note.output)
    assert f"psamvault add --claim {credential_code}" in credential.output
    assert f"psamvault note-add --claim {note_code}" in note.output

    assert store.peek(credential_code)["family"] == store.FAMILY_CREDENTIAL
    assert store.peek(credential_code)["login_url"] == "https://github.com/login"
    assert store.peek(note_code)["family"] == store.FAMILY_NOTE
    assert store.peek(note_code)["category"] == "ssh"


def test_creating_a_claim_is_audited_without_the_value(monkeypatch):
    as_agent(monkeypatch)

    result = invoke(["ak-add", "github-prod", "--service", "GitHub"])

    claim_rows = [row for row in rows() if row["decision"] == "claim-created"]
    assert len(claim_rows) == 1
    assert claim_rows[0]["command"] == "ak-add"
    assert claim_rows[0]["entry"] == "github-prod"
    assert claim_rows[0]["caller"] == "agent"
    assert SECRET not in audit.AUDIT_FILE.read_text(encoding="utf-8")


# ── the human's half ─────────────────────────────────────────────────────────


def test_the_human_fills_the_claim_and_the_code_is_spent(monkeypatch, httpx_mock):
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/apikeys", json={"detail": "ok"}, status_code=200
    )

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 0, result.output
    assert SECRET not in result.output, "the value a human typed is never echoed"
    assert store.load(record["code"]) is None, "the code is spent by a successful fill"

    body = json.loads(httpx_mock.get_requests()[0].content)
    assert decrypt_api_key(VEK, body["encrypted_blob"], body["iv"])["api_key"] == SECRET

    filled = [row for row in rows() if row["decision"] == "claim-filled"]
    assert len(filled) == 1 and filled[0]["entry"] == "github-prod"


def test_the_fill_shows_the_name_and_service_before_prompting(monkeypatch, httpx_mock):
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/apikeys", json={"detail": "ok"}, status_code=200
    )

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert "github-prod (GitHub)" in result.output


def test_a_failed_store_leaves_the_claim_fillable(monkeypatch, httpx_mock):
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/apikeys", json={"detail": "exists"}, status_code=409
    )

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 1
    assert store.load(record["code"]) is not None, "a typo must not cost the human the code"
    assert [r for r in rows() if r["decision"] == "claim-filled"] == []


def test_the_fill_works_for_a_credential(monkeypatch, httpx_mock):
    record = store.create(store.FAMILY_CREDENTIAL, "github.com", login_url="https://github.com")
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/vault", json={"detail": "ok"}, status_code=200
    )

    result = invoke(["add", "--claim", record["code"]], input=f"alice@example.com\n{SECRET}\n")

    assert result.exit_code == 0, result.output
    assert SECRET not in result.output
    body = json.loads(httpx_mock.get_requests()[0].content)
    stored = decrypt_credentials(VEK, body["encrypted_blob"], body["iv"])
    assert stored["username"] == "alice@example.com"
    assert stored["password"] == SECRET


def test_the_fill_works_for_a_note(monkeypatch, httpx_mock):
    record = store.create(store.FAMILY_NOTE, "ssh-key", category="ssh")
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/notes", json={"detail": "ok"}, status_code=200
    )

    result = invoke(["note-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 0, result.output
    body = json.loads(httpx_mock.get_requests()[0].content)
    assert decrypt_note(VEK, body["encrypted_blob"], body["iv"])["content"] == SECRET


# ── the two refusals ─────────────────────────────────────────────────────────


def test_an_agent_cannot_fill_a_claim(monkeypatch):
    as_agent(monkeypatch)
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 1
    assert "agent terminal detected" in result.output
    assert record["code"] in result.output and "--claim" in result.output
    assert SECRET not in result.output
    assert store.load(record["code"]) is not None, "the claim is untouched"

    denied = [row for row in rows() if row["decision"] == "deny"]
    assert [row["entry"] for row in denied] == ["github-prod"]


@pytest.mark.parametrize(
    "args, name",
    [
        (["ak-add", "github-prod", "--service", "GitHub", "--key", SECRET], "github-prod"),
        (["add", "github.com", "--user", "me@example.com", "--pass", SECRET], "github.com"),
        (["note-add", "ssh-key", "--content", SECRET], "ssh-key"),
    ],
)
def test_an_agent_cannot_put_a_secret_on_the_command_line(monkeypatch, args, name):
    as_agent(monkeypatch)
    add_calls = []

    with patch("api_client.add_api_key_entry", lambda **kw: add_calls.append(kw)), \
         patch("api_client.add_vault_entry", lambda **kw: add_calls.append(kw)), \
         patch("api_client.add_note_entry", lambda **kw: add_calls.append(kw)):
        result = invoke(args)

    assert result.exit_code == 1
    assert "blocked in this context" in result.output
    assert "argv" in result.output
    assert SECRET not in result.output
    assert add_calls == [], "nothing was stored"

    denied = [row for row in rows() if row["decision"] == "deny"]
    assert denied and denied[-1]["entry"] == name


def test_the_argv_refusal_names_the_claim_flow_instead(monkeypatch):
    as_agent(monkeypatch)

    result = invoke(["ak-add", "github-prod", "--service", "GitHub", "--key", SECRET])

    assert "psamvault ak-add github-prod --service GitHub" in result.output
    assert "claim" in result.output.lower()


def test_a_human_may_still_pass_a_value(httpx_mock):
    """The guard blocks agents, not people: this is today's behaviour, unchanged."""
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/apikeys", json={"detail": "ok"}, status_code=200
    )

    result = invoke(["ak-add", "github-prod", "--service", "GitHub", "--key", SECRET])

    assert result.exit_code == 0, result.output
    assert store.list_records() == [], "a human passing a value creates no claim"


def test_the_refusal_error_is_the_typed_one():
    assert issubclass(IngressBlockedError, Exception)
    assert claim_flow.IngressBlockedError is IngressBlockedError


# ── pending ──────────────────────────────────────────────────────────────────


def test_pending_lists_a_live_claim_with_the_time_left(monkeypatch):
    as_agent(monkeypatch)
    code = code_in(invoke(["ak-add", "github-prod", "--service", "GitHub"]).output)

    result = invoke(["pending"])

    assert result.exit_code == 0
    assert code in result.output
    assert "github-prod (GitHub)" in result.output
    assert "m left" in result.output


def test_pending_with_nothing_outstanding_says_so():
    result = invoke(["pending"])

    assert result.exit_code == 0
    assert "No claims are waiting" in result.output


def test_pending_cancel_drops_the_code(monkeypatch):
    as_agent(monkeypatch)
    code = code_in(invoke(["ak-add", "github-prod", "--service", "GitHub"]).output)

    cancelled = invoke(["pending", "--cancel", code])
    listed = invoke(["pending"])
    refill = invoke(["ak-add", "--claim", code])

    assert cancelled.exit_code == 0
    assert "cancelled" in cancelled.output
    assert code not in listed.output
    assert refill.exit_code == 1
    assert "No claim matches" in refill.output


def test_an_unknown_code_is_refused_cleanly():
    result = invoke(["ak-add", "--claim", "PV-AAAA-AAAA"])

    assert result.exit_code == 1
    assert "No claim matches" in result.output
    assert "Traceback" not in result.output


def test_an_expired_code_is_refused_with_its_own_message(monkeypatch):
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")
    monkeypatch.setattr(store, "_now", lambda: store._parse(record["expires_at"]) + __import__("datetime").timedelta(seconds=1))

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 1
    assert "expired" in result.output.lower()


def test_a_code_from_another_family_points_at_the_right_command(monkeypatch):
    record = store.create(store.FAMILY_NOTE, "ssh-key")

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    assert result.exit_code == 1
    assert "not this command" in result.output
    assert f"psamvault note-add --claim {record['code']}" in result.output


# ── the cut, and the boundary ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "argv, flag",
    [
        (["ak-add", "--help"], "--wait"),
        (["ak-add", "--help"], "--timeout"),
        (["ak-add", "--help"], "--from-file"),
        (["ak-add", "--help"], "--from-key"),
        (["ak-add", "--help"], "--from-env"),
        (["ak-add", "--help"], "--delete-source"),
        (["add", "--help"], "--wait"),
        (["note-add", "--help"], "--timeout"),
        (["pending", "--help"], "--code"),
    ],
)
def test_the_removed_flags_are_not_in_help(argv, flag):
    result = runner.invoke(app, argv, terminal_width=200)

    assert result.exit_code == 0
    assert flag not in result.output


def test_no_secret_reaches_any_produced_artifact(monkeypatch, httpx_mock, tmp_path):
    """The whole point, checked against the files rather than the transcript."""
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub")
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/apikeys", json={"detail": "ok"}, status_code=200
    )

    result = invoke(["ak-add", "--claim", record["code"]], input=f"{SECRET}\n")

    produced = [
        audit.AUDIT_FILE,
        *sorted((tmp_path / "pending").glob("*.json")),
        tmp_path / "policy.json",
    ]
    for path in produced:
        if path.exists():
            assert SECRET not in path.read_text(encoding="utf-8"), f"{path.name} holds the value"
    assert SECRET not in result.output
    assert list((tmp_path / "pending").glob("*.json")) == [], "nothing is left behind either way"
