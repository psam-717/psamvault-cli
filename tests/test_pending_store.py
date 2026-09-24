"""The pending-claim store — metadata only, single-use, TTL-bound.

Layer 1: the store on its own, with no CLI in the way. The flows that use it
(claim creation from an agent context, the fill from a human terminal, `--wait`)
are in test_blind_ingress.py.

What these tests are protecting, in order of how badly it would hurt:

* **a secret never lands in the claim file** — anything running as the user, the
  agent included, can read ``~/.psamvault/pending/``;
* **a code is never reused and never overwritten** — a second claim that
  collided with a live one must re-roll, not clobber the first;
* **expiry is enforced on access** — a laptop that was asleep for a week does
  not wake up holding live claims.
"""
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

import pending_store as store

FAMILY = store.FAMILY_API_KEY


def on_disk() -> list[str]:
    return sorted(p.name for p in store.PENDING_DIR.glob("*.json"))


def later(seconds: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


# ── the code itself ───────────────────────────────────────────────────────────


def test_code_is_prefixed_and_crockford_base32():
    code = store.generate_code()
    prefix, first, second = code.split("-")
    assert prefix == "PV"
    assert len(first) == 4 and len(second) == 4
    assert set(first + second) <= set(store.CODE_ALPHABET)
    # Crockford omits I, L, O and U so a code read over the phone cannot be
    # transcribed into a different one.
    assert not set("ILOU") & set(first + second)


def test_codes_do_not_repeat_in_a_small_sample():
    codes = {store.generate_code() for _ in range(200)}
    assert len(codes) == 200


@pytest.mark.parametrize(
    "typed",
    ["PV-4F2K-91QX", "pv-4f2k-91qx", "pv4f2k91qx", "4F2K-91QX", " pv 4f2k 91qx "],
)
def test_a_typed_code_is_normalised(typed):
    assert store.normalize_code(typed) == "PV-4F2K-91QX"


@pytest.mark.parametrize("bad", ["", "PV-123", "PV-4F2K-91Q", "PV-4F2K-91QI", "not-a-code"])
def test_a_malformed_code_is_rejected(bad):
    with pytest.raises(ValueError):
        store.normalize_code(bad)


# ── creating a claim ──────────────────────────────────────────────────────────


def test_create_writes_metadata_only(tmp_path):
    record = store.create(FAMILY, "github-prod", service="GitHub", notes="read-only")

    assert record["code"].startswith("PV-")
    assert record["family"] == FAMILY
    assert record["name"] == "github-prod"
    assert record["service"] == "GitHub"
    assert record["notes"] == "read-only"
    assert record["status"] == store.STATUS_PENDING
    assert record["filled_at"] is None
    assert record["ttl_seconds"] == store.DEFAULT_TTL_SECONDS

    # The exact field set is the invariant: a new field cannot be added without
    # a test noticing, because a secret-bearing field is the one mistake here
    # that nothing else would catch.
    assert set(record) == {
        "code",
        "family",
        "name",
        "service",
        "notes",
        "login_url",
        "category",
        "username",
        "created_at",
        "expires_at",
        "ttl_seconds",
        "status",
        "filled_at",
    }

    stored = json.loads((store.PENDING_DIR / f"{record['code']}.json").read_text())
    assert stored == record


def test_create_rejects_an_unknown_family():
    with pytest.raises(ValueError):
        store.create("bitcoin-wallet", "x")


def test_create_clamps_the_ttl_into_the_supported_window():
    assert store.create(FAMILY, "a", ttl_seconds=5)["ttl_seconds"] == store.MIN_TTL_SECONDS
    assert store.create(FAMILY, "b", ttl_seconds=99999)["ttl_seconds"] == store.MAX_TTL_SECONDS


def test_create_rerolls_instead_of_overwriting_a_live_claim(monkeypatch):
    first = store.create(FAMILY, "github-prod", service="GitHub")

    calls = {"n": 0}

    def colliding_code():
        calls["n"] += 1
        return first["code"] if calls["n"] == 1 else "PV-ZZZZ-ZZZZ"

    monkeypatch.setattr(store, "generate_code", colliding_code)
    second = store.create(FAMILY, "other-prod")

    assert second["code"] == "PV-ZZZZ-ZZZZ"
    assert calls["n"] == 2, "a collision must trigger exactly one re-roll"
    # ...and the live claim is untouched, not silently replaced.
    assert store.peek(first["code"])["name"] == "github-prod"
    assert len(on_disk()) == 2


def test_create_gives_up_rather_than_clobbering(monkeypatch):
    first = store.create(FAMILY, "github-prod")
    monkeypatch.setattr(store, "generate_code", lambda: first["code"])

    with pytest.raises(RuntimeError):
        store.create(FAMILY, "other-prod")

    assert store.peek(first["code"])["name"] == "github-prod"
    assert len(on_disk()) == 1


# ── reading, expiring, filling ────────────────────────────────────────────────


def test_load_accepts_any_reasonable_typing_of_the_code():
    record = store.create(FAMILY, "github-prod")

    assert store.load(record["code"].lower())["name"] == "github-prod"
    assert store.load(record["code"].replace("-", ""))["name"] == "github-prod"


def test_an_unknown_code_is_none_not_an_error():
    assert store.load("PV-AAAA-AAAA") is None
    assert store.peek("nonsense") is None


def test_an_expired_claim_is_pruned_when_it_is_touched():
    record = store.create(FAMILY, "github-prod", ttl_seconds=store.MIN_TTL_SECONDS)

    assert store.load(record["code"], now=later(store.MIN_TTL_SECONDS + 1)) is None
    assert on_disk() == [], "an expired claim is deleted, not left as a trap"


def test_peek_reports_an_expired_claim_so_the_error_can_say_which():
    record = store.create(FAMILY, "github-prod", ttl_seconds=store.MIN_TTL_SECONDS)

    peeked = store.peek(record["code"], now=later(store.MIN_TTL_SECONDS + 1))
    assert peeked is not None
    assert store.is_expired(peeked, now=later(store.MIN_TTL_SECONDS + 1)) is True


def test_mark_filled_flips_the_status_and_is_single_use():
    record = store.create(FAMILY, "github-prod")

    filled = store.mark_filled(record["code"])
    assert filled["status"] == store.STATUS_FILLED
    assert filled["filled_at"]

    # A filled claim is no longer pending, still readable as evidence, and
    # refuses a second fill — the code is consumed.
    assert store.pending() == []
    assert store.load(record["code"])["status"] == store.STATUS_FILLED
    assert store.mark_filled(record["code"]) is None


def test_an_expired_claim_cannot_be_filled():
    record = store.create(FAMILY, "github-prod", ttl_seconds=store.MIN_TTL_SECONDS)
    assert store.mark_filled(record["code"], now=later(store.MIN_TTL_SECONDS + 1)) is None


def test_a_filled_claim_is_report_kept_then_pruned():
    record = store.create(FAMILY, "github-prod")
    store.mark_filled(record["code"])

    retention = store.FILLED_RETENTION_SECONDS
    assert store.load(record["code"], now=later(retention - 1))["status"] == store.STATUS_FILLED
    assert store.load(record["code"], now=later(retention + 1)) is None
    assert on_disk() == []


# ── listing and cancelling ────────────────────────────────────────────────────


def test_listing_puts_pending_first_and_reports_remaining_time():
    store.create(FAMILY, "first", ttl_seconds=600)
    second = store.create(FAMILY, "second", ttl_seconds=600)
    store.mark_filled(second["code"])

    records = store.list_records()
    assert [r["name"] for r in records] == ["first", "second"]
    assert [r["status"] for r in records] == [store.STATUS_PENDING, store.STATUS_FILLED]

    assert 0 < store.seconds_remaining(records[0]) <= 600
    assert store.seconds_remaining(records[1]) == 0, "a filled claim has no countdown"


def test_listing_prunes_expired_claims_and_survives_a_corrupt_file():
    store.create(FAMILY, "live")
    store.create(FAMILY, "dead", ttl_seconds=store.MIN_TTL_SECONDS)
    (store.PENDING_DIR / "PV-C0RP-T000.json").write_text("{not json")

    records = store.list_records(now=later(store.MIN_TTL_SECONDS + 1))

    assert [r["name"] for r in records] == ["live"]
    assert on_disk() == ["PV-" + records[0]["code"].split("-", 1)[1] + ".json"]


def test_cancel_removes_the_claim_and_the_code_stops_working():
    record = store.create(FAMILY, "github-prod")

    assert store.delete(record["code"]) is True
    assert store.delete(record["code"]) is False
    assert store.load(record["code"]) is None


# ── the file on disk ──────────────────────────────────────────────────────────


@pytest.mark.skipif(
    os.name != "posix", reason="Windows reports 0o666 for every file regardless of its ACLs"
)
def test_the_claim_directory_and_files_are_private():
    record = store.create(FAMILY, "github-prod")
    path = store.PENDING_DIR / f"{record['code']}.json"

    assert store.PENDING_DIR.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600
