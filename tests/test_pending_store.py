"""The claim store — metadata only, single-use, gone when it expires.

These are the invariants the security story rests on: exactly what a claim file
holds, how long it lives, and that spending it leaves nothing behind. Everything
else about the ingress feature is a CLI test (``test_blind_ingress.py``).
"""
import json
import os
from datetime import timedelta

import pytest

import pending_store as store

# The whole record. If a field is ever added, this test is where it gets noticed:
# a claim must never grow into something worth stealing.
CLAIM_FIELDS = {
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
}


def test_a_claim_holds_metadata_only():
    record = store.create(store.FAMILY_API_KEY, "github-prod", service="GitHub", notes="work")

    path = store._path(record["code"])
    assert path.exists()
    on_disk = json.loads(path.read_text(encoding="utf-8"))

    assert set(on_disk) == CLAIM_FIELDS, "a claim carries no field beyond the metadata set"
    assert on_disk["code"] == record["code"]
    assert on_disk["family"] == store.FAMILY_API_KEY
    assert on_disk["name"] == "github-prod"
    assert on_disk["service"] == "GitHub"


def test_the_claim_file_is_owner_only():
    if os.name == "nt":
        pytest.skip("Windows reports one mode for every file; the user ACL is the control there")

    record = store.create(store.FAMILY_NOTE, "wifi")

    assert oct(store._path(record["code"]).stat().st_mode & 0o777) == "0o600"


def test_a_code_is_crockford_and_reads_back_loosely():
    code = store.generate_code()
    body = code.replace(f"{store.CODE_PREFIX}-", "").replace("-", "")

    assert code.startswith(f"{store.CODE_PREFIX}-")
    assert len(body) == store.CODE_CHARS
    assert all(ch in store.CODE_ALPHABET for ch in body)
    # Crockford drops the letters that get mistyped when a code is read aloud
    for ambiguous in "ILOU":
        assert ambiguous not in body

    assert store.normalize_code(code.lower()) == code
    assert store.normalize_code(body) == code
    assert store.normalize_code(f"pv {body[:4]} {body[4:]}") == code
    with pytest.raises(ValueError):
        store.normalize_code("PV-TOO-SHORT")


def test_a_collision_re_rolls_and_never_overwrites_the_existing_claim(monkeypatch):
    first = store.create(store.FAMILY_API_KEY, "one", service="S")
    monkeypatch.setattr(store, "generate_code", lambda: first["code"])

    with pytest.raises(RuntimeError):
        store.create(store.FAMILY_API_KEY, "two", service="S")

    assert store.load(first["code"])["name"] == "one", "the first claim survived the attempt"


def test_an_expired_claim_is_pruned_on_sight():
    record = store.create(
        store.FAMILY_API_KEY, "old", service="S", ttl_seconds=store.MIN_TTL_SECONDS
    )
    later = store._now() + timedelta(seconds=store.MIN_TTL_SECONDS + 1)

    assert store.load(record["code"], now=later) is None
    assert not store._path(record["code"]).exists(), "an expired claim does not linger on disk"


def test_listing_keeps_live_claims_and_prunes_the_rest():
    live = store.create(store.FAMILY_CREDENTIAL, "github.com")
    stale = store.create(store.FAMILY_NOTE, "wifi", ttl_seconds=store.MIN_TTL_SECONDS)
    later = store._now() + timedelta(seconds=store.MIN_TTL_SECONDS + 1)

    listed = store.list_records(now=later)

    assert [r["code"] for r in listed] == [live["code"]]
    assert not store._path(stale["code"]).exists()


def test_live_claims_list_oldest_first():
    base = store._now()
    store.create(store.FAMILY_NOTE, "second", now=base + timedelta(seconds=60))
    store.create(store.FAMILY_API_KEY, "first", service="S", now=base)

    names = [r["name"] for r in store.list_records(now=base + timedelta(seconds=61))]

    assert names == ["first", "second"]


def test_spending_a_claim_deletes_it():
    record = store.create(store.FAMILY_API_KEY, "k", service="S")

    spent = store.consume(record["code"])

    assert spent["code"] == record["code"]
    assert not store._path(record["code"]).exists(), "a spent code leaves nothing behind"
    assert store.consume(record["code"]) is None, "single use"
    assert store.load(record["code"]) is None


def test_spending_refuses_an_expired_or_unknown_claim():
    record = store.create(
        store.FAMILY_API_KEY, "k", service="S", ttl_seconds=store.MIN_TTL_SECONDS
    )
    later = store._now() + timedelta(seconds=store.MIN_TTL_SECONDS + 1)

    assert store.consume(record["code"], now=later) is None
    assert store.consume("PV-AAAA-AAAA") is None


def test_cancelling_removes_the_claim():
    record = store.create(store.FAMILY_NOTE, "wifi")

    assert store.delete(record["code"]) is True
    assert store.delete(record["code"]) is False, "cancelling twice is not an error, just false"
    assert store.load(record["code"]) is None


def test_remaining_time_counts_down():
    record = store.create(store.FAMILY_API_KEY, "k", service="S")

    assert store.seconds_remaining(record) == pytest.approx(store.DEFAULT_TTL_SECONDS, abs=2)

    half = store._now() + timedelta(seconds=store.DEFAULT_TTL_SECONDS // 2)
    assert store.seconds_remaining(record, now=half) == pytest.approx(
        store.DEFAULT_TTL_SECONDS // 2, abs=2
    )


def test_the_lifetime_is_clamped_to_the_supported_window():
    record = store.create(store.FAMILY_API_KEY, "k", service="S", ttl_seconds=5)

    assert store.seconds_remaining(record) <= store.MIN_TTL_SECONDS
    assert store.clamp_ttl(99999) == store.MAX_TTL_SECONDS
    assert store.clamp_ttl("nonsense") == store.DEFAULT_TTL_SECONDS


def test_an_unknown_family_is_refused():
    with pytest.raises(ValueError):
        store.create("wallet", "x")
