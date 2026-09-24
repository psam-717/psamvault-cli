"""Migrating a value that is already on this machine — `--from-file`, `--from-env`.

The feature is for the case where the secret is already sitting in a file the
agent must not read out: a key inside a `.env`, or a whole file that *is* the
secret (a service-account JSON, a `.pem`). The CLI reads it and encrypts it, so
the value never appears in the agent's output, and `--delete-source` can remove
the one line it came from.

Two shapes, one flag apart:
    --from-file ./.env --from-key STRIPE_TEST_KEY   one NAME= line
    --from-file ./service-account.json              the whole file is the secret
"""
import json
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

import claim_flow
import pending_store as store
from crypto import decrypt_api_key
from main import app

runner = CliRunner()
BASE = "https://test.example.com"
VEK = bytes(range(32))
SESSION = {"access_token": "t", "refresh_token": "r", "vek": VEK.hex(), "kdf_salt": "aa" * 32}

SECRET = "«from-the-file-not-the-terminal»"


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


def stored_key(httpx_mock):
    """The value that actually reached the server, decrypted."""
    body = json.loads(httpx_mock.get_requests()[0].content)
    return decrypt_api_key(VEK, body["encrypted_blob"], body["iv"])


def ok_post(httpx_mock):
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/apikeys", json={"detail": "ok"}, status_code=200
    )


def write_env(tmp_path, text):
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    return path


# ── one line out of a .env ───────────────────────────────────────────────────


def test_a_key_is_taken_out_of_a_dotenv_without_being_printed(monkeypatch, tmp_path, httpx_mock):
    as_agent(monkeypatch)
    env = write_env(tmp_path, f"OTHER=other-value\nSTRIPE_TEST_KEY={SECRET}\n")
    ok_post(httpx_mock)

    result = invoke(
        ["ak-add", "stripe-test", "--service", "Stripe",
         "--from-file", str(env), "--from-key", "STRIPE_TEST_KEY"]
    )

    assert result.exit_code == 0
    assert SECRET not in result.output
    assert stored_key(httpx_mock)["api_key"] == SECRET
    assert env.read_text(encoding="utf-8").count(SECRET) == 1, "the source file is untouched"


def test_an_agent_may_migrate_a_file_it_must_not_read(monkeypatch, tmp_path, httpx_mock):
    """This is the path an agent uses to hand a secret over without seeing it."""
    as_agent(monkeypatch)
    env = write_env(tmp_path, f"KEY={SECRET}\n")
    ok_post(httpx_mock)

    result = invoke(["ak-add", "k", "--service", "S", "--from-file", str(env), "--from-key", "KEY"])

    assert result.exit_code == 0
    assert SECRET not in result.output
    assert store.list_records() == [], "a migration is not a claim — nothing is pending"


def test_quotes_and_export_are_handled(tmp_path):
    env = write_env(
        tmp_path,
        '# a comment\n\nexport QUOTED="two words"\nSINGLE=\'single quoted\'\nUNQUOTED=plain # trailing\n',
    )
    text = env.read_text(encoding="utf-8")

    assert claim_flow.parse_env_value(text, "QUOTED") == "two words"
    assert claim_flow.parse_env_value(text, "SINGLE") == "single quoted"
    assert claim_flow.parse_env_value(text, "UNQUOTED") == "plain"
    assert claim_flow.parse_env_value(text, "MISSING") is None


def test_a_missing_key_lists_the_names_it_did_find(tmp_path, httpx_mock):
    env = write_env(tmp_path, f"ALPHA={SECRET}\nBETA=another\n")

    result = invoke(
        ["ak-add", "k", "--service", "S", "--from-file", str(env), "--from-key", "GAMMA"]
    )

    assert result.exit_code == 1
    assert "GAMMA" in result.output
    assert "ALPHA" in result.output and "BETA" in result.output
    assert SECRET not in result.output, "the hint names keys, never values"


def test_a_missing_file_is_a_clean_error(tmp_path):
    result = invoke(
        ["ak-add", "k", "--service", "S", "--from-file", str(tmp_path / "nope.env"), "--from-key", "K"]
    )

    assert result.exit_code == 1
    assert "Traceback" not in result.output


# ── the whole file is the secret ─────────────────────────────────────────────


def test_a_whole_file_can_be_the_secret(tmp_path, httpx_mock):
    credential_file = tmp_path / "service-account.json"
    credential_file.write_text(json.dumps({"private_key": SECRET}), encoding="utf-8")
    ok_post(httpx_mock)

    result = invoke(["ak-add", "sa-prod", "--service", "Google", "--from-file", str(credential_file)])

    assert result.exit_code == 0
    assert SECRET not in result.output
    # whole-file mode stores the file's text as-is — no parsing, no rewriting
    assert stored_key(httpx_mock)["api_key"] == credential_file.read_text(encoding="utf-8")


# ── --from-env ───────────────────────────────────────────────────────────────


def test_a_key_can_come_from_the_environment(monkeypatch, httpx_mock):
    monkeypatch.setenv("MIGRATE_ME", SECRET)
    ok_post(httpx_mock)

    result = invoke(["ak-add", "k", "--service", "S", "--from-env", "MIGRATE_ME"])

    assert result.exit_code == 0
    assert SECRET not in result.output
    assert stored_key(httpx_mock)["api_key"] == SECRET


def test_an_unset_variable_is_a_clean_error():
    result = invoke(["ak-add", "k", "--service", "S", "--from-env", "NOT_SET_ANYWHERE"])

    assert result.exit_code == 1
    assert "NOT_SET_ANYWHERE" in result.output
    assert "Traceback" not in result.output


# ── --delete-source ──────────────────────────────────────────────────────────


def test_delete_source_removes_the_one_line_and_keeps_a_backup(tmp_path, httpx_mock):
    env = write_env(tmp_path, f"KEEP=keep-me\nMOVE={SECRET}\nALSO_KEEP=also-me\n")
    ok_post(httpx_mock)

    result = invoke(
        ["ak-add", "k", "--service", "S",
         "--from-file", str(env), "--from-key", "MOVE", "--delete-source"]
    )

    assert result.exit_code == 0
    remaining = env.read_text(encoding="utf-8")
    assert "MOVE=" not in remaining
    assert "KEEP=keep-me" in remaining and "ALSO_KEEP=also-me" in remaining

    backup = tmp_path / ".env.bak"
    assert backup.exists()
    assert SECRET in backup.read_text(encoding="utf-8"), "the original is recoverable"


def test_delete_source_is_refused_without_a_key(tmp_path, httpx_mock):
    """A whole-file source is never deleted: that file IS the secret."""
    source = tmp_path / "secret.pem"
    source.write_text(SECRET, encoding="utf-8")

    result = invoke(
        ["ak-add", "k", "--service", "S", "--from-file", str(source), "--delete-source"]
    )

    assert result.exit_code == 1
    assert source.exists()
    assert source.read_text(encoding="utf-8") == SECRET


# ── contradictory flags ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "args, expected",
    [
        (["ak-add", "k", "--service", "S", "--from-key", "K"], "--from-key"),
        (["ak-add", "k", "--service", "S", "--from-file", ".env", "--from-env", "V"], "--from-env"),
        (["ak-add", "k", "--from-file", "./x"], "--service"),
        (["ak-add", "k", "--service", "S", "--key", "v", "--from-env", "V"], "one of"),
    ],
)
def test_contradictory_flags_are_refused_before_anything_happens(args, expected, tmp_path):
    add_key = Mock()

    with patch("api_client.add_api_key_entry", add_key):
        result = invoke(args)

    assert result.exit_code == 1
    assert expected in result.output
    add_key.assert_not_called()
