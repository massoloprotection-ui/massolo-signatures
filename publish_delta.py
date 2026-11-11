#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Massolo - publication quotidienne du delta de signatures.

Tourne dans GitHub Actions (voir publish-delta.yml), JAMAIS chez les clients.
Lit l'export "recent" de MalwareBazaar avec la cle ABUSECH_KEY (secret du depot),
le fusionne avec le delta precedemment publie (fenetre glissante de 14 jours),
puis ecrit :
  out/delta.csv.gz   les nouveaux hashes (sha256 valides uniquement)
  out/manifest.json  version, SHA-256 du .gz, signature Ed25519 (si SIGNING_KEY)

Variables d'environnement :
  ABUSECH_KEY         cle abuse.ch (obligatoire sauf avec --export-file)
  GITHUB_REPOSITORY   "proprietaire/depot" (sert a construire l'URL publique)
  SIGNING_KEY         cle PRIVEE Ed25519, base64 de 32 octets (optionnelle)
"""
import argparse
import base64
import csv
import gzip
import hashlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

EXPORT_URL = "https://bazaar.abuse.ch/export/csv/recent/"
WINDOW_DAYS = 14
MIN_NEW_ROWS = 50          # en dessous : flux vide ou en panne, on ne publie pas
MAX_NEW_ROWS = 500_000     # au dessus : flux anormal, on ne publie pas
MAX_DOWNLOAD = 300 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = {32: re.compile(r"^[0-9a-f]{32}$"), 40: re.compile(r"^[0-9a-f]{40}$")}
HEADER = ["first_seen", "sha256", "md5", "sha1", "file_name", "file_type", "signature"]
UA = "Massolo-Signatures-Publisher/1.0"


def fetch_export(key: str) -> bytes:
    req = urllib.request.Request(EXPORT_URL, headers={"Auth-Key": key, "User-Agent": UA})
    buf = bytearray()
    with urllib.request.urlopen(req, timeout=120) as r:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_DOWNLOAD:
                raise RuntimeError("export trop volumineux")
    return bytes(buf)


def _clean_hex(value: str, length: int) -> str:
    value = (value or "").strip().lower()
    return value if HEX_RE[length].match(value) else ""


def parse_export(raw: bytes) -> dict:
    """Export MalwareBazaar (zip ou CSV brut) -> {sha256: ligne}."""
    if zipfile.is_zipfile(io.BytesIO(raw)):
        z = zipfile.ZipFile(io.BytesIO(raw))
        raw = z.read(z.namelist()[0])
    text = raw.decode("utf-8", errors="ignore")
    lines = (ln for ln in text.splitlines() if ln and not ln.startswith("#"))
    rows = {}
    for parts in csv.reader(lines):
        if not parts or parts[0].strip().lower().startswith("first_seen"):
            continue
        if len(parts) < 9:
            continue
        sha256 = parts[1].strip().lower()
        if not SHA256_RE.match(sha256):
            continue
        sig = parts[8].strip()
        if not sig or sig.lower() in ("n/a", "na", "-"):
            sig = "Hash suspect non classifié (MalwareBazaar)"
        rows[sha256] = [
            parts[0].strip(), sha256,
            _clean_hex(parts[2], 32), _clean_hex(parts[3], 40),
            parts[5].strip(), parts[6].strip(), sig,
        ]
    return rows


def load_previous(path_or_url: str) -> dict:
    """Delta precedent (fichier local ou URL). 404 / absent -> vide."""
    try:
        if not path_or_url.lower().startswith(("http://", "https://")):
            raw = open(path_or_url, "rb").read()   # fichier local (tests)
        else:
            req = urllib.request.Request(path_or_url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=120) as r:
                raw = r.read(MAX_DOWNLOAD)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}
        raise
    except FileNotFoundError:
        return {}
    text = gzip.GzipFile(fileobj=io.BytesIO(raw)).read().decode("utf-8", errors="ignore")
    rows = {}
    for parts in csv.reader(io.StringIO(text)):
        if len(parts) == len(HEADER) and parts[0] != "first_seen" and SHA256_RE.match(parts[1]):
            rows[parts[1]] = parts
    return rows


def _parse_ts(value: str):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def merge(old: dict, new: dict, now: datetime) -> dict:
    merged = dict(old)
    merged.update(new)
    limit = now - timedelta(days=WINDOW_DAYS)
    kept = {}
    for sha, row in merged.items():
        ts = _parse_ts(row[0])
        if ts is None or ts >= limit:
            kept[sha] = row
    return kept


def write_gz(rows: dict, path: str):
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(HEADER)
    for row in sorted(rows.values(), key=lambda r: (r[0], r[1])):
        w.writerow(row)
    with open(path, "wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, compresslevel=9, mtime=0) as g:
            g.write(out.getvalue().encode("utf-8"))


def sign(digest_hex: str, key_b64: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_b64.strip()))
    return base64.b64encode(priv.sign(digest_hex.encode("ascii"))).decode("ascii")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out")
    ap.add_argument("--export-file", help="export local (test), sans reseau")
    ap.add_argument("--previous", help="delta precedent : fichier ou URL")
    ap.add_argument("--base-url", help="URL publique du dossier de release")
    a = ap.parse_args()

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    base = (a.base_url or f"https://github.com/{repo}/releases/download/latest/").rstrip("/") + "/"
    if not a.base_url and not repo:
        sys.exit("ERREUR : GITHUB_REPOSITORY absent et --base-url non fourni")
    previous = a.previous or (base + "delta.csv.gz")

    if a.export_file:
        raw = open(a.export_file, "rb").read()
    else:
        key = os.environ.get("ABUSECH_KEY", "").strip()
        if not key:
            sys.exit("ERREUR : secret ABUSECH_KEY absent")
        raw = fetch_export(key)

    new = parse_export(raw)
    print(f"export : {len(new):,} hashes valides")
    if not (MIN_NEW_ROWS <= len(new) <= MAX_NEW_ROWS):
        sys.exit(f"ERREUR : {len(new):,} lignes hors de [{MIN_NEW_ROWS}, {MAX_NEW_ROWS}], rien publie")

    now = datetime.now(timezone.utc)
    merged = merge(load_previous(previous), new, now)
    os.makedirs(a.out, exist_ok=True)
    gz_path = os.path.join(a.out, "delta.csv.gz")
    write_gz(merged, gz_path)
    gz = open(gz_path, "rb").read()
    digest = hashlib.sha256(gz).hexdigest()

    signing_key = os.environ.get("SIGNING_KEY", "").strip()
    manifest = {
        "format": 1,
        "version": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rows": len(merged),
        "window_days": WINDOW_DAYS,
        "url": base + "delta.csv.gz",
        "sha256": digest,
        "size": len(gz),
        "signature": sign(digest, signing_key) if signing_key else "",
    }
    with open(os.path.join(a.out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"delta : {len(merged):,} lignes, {len(gz)/1e6:.1f} Mo, signe={'oui' if signing_key else 'non'}")


if __name__ == "__main__":
    main()
