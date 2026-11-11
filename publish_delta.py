#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Massolo - publication quotidienne du delta de signatures.

Tourne dans GitHub Actions (voir publish-delta.yml), JAMAIS chez les clients.
Lit l'export "recent" de MalwareBazaar (48 dernieres heures) avec la cle ABUSECH_KEY
(secret du depot), ou, s'il est indisponible, l'API get_recent (mode degrade),
le fusionne avec le delta precedemment publie (fenetre glissante de 7 jours),
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

# Nouvelle adresse documentee par abuse.ch (l'ancienne /export/csv/... repond 410 Gone).
# La cle fait partie de l'URL : ne jamais l'afficher dans les logs.
EXPORT_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
API_URL = "https://mb-api.abuse.ch/api/v1/"
WINDOW_DAYS = 7
MIN_NEW_ROWS = 50          # en dessous : flux vide ou en panne, on ne publie pas
MAX_NEW_ROWS = 500_000     # au dessus : flux anormal, on ne publie pas
MAX_DOWNLOAD = 300 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = {32: re.compile(r"^[0-9a-f]{32}$"), 40: re.compile(r"^[0-9a-f]{40}$")}
HEADER = ["first_seen", "sha256", "md5", "sha1", "file_name", "file_type", "signature"]
UA = "Massolo-Signatures-Publisher/1.0"


def fetch_export(key: str) -> bytes:
    req = urllib.request.Request(EXPORT_URL.format(key=key), headers={"User-Agent": UA})
    buf = bytearray()
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_DOWNLOAD:
                    raise RuntimeError("export trop volumineux")
    except urllib.error.HTTPError as e:
        # on n'affiche jamais l'URL : elle contient la cle
        raise RuntimeError(f"HTTP {e.code} {e.reason}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"connexion impossible ({e.reason})") from None
    return bytes(buf)


def _api_post(key: str, selector: str) -> list:
    data = f"query=get_recent&selector={selector}".encode("ascii")
    req = urllib.request.Request(
        API_URL, data=data, method="POST",
        headers={"Auth-Key": key, "User-Agent": UA,
                 "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            result = json.loads(r.read(50 * 1024 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"API HTTP {e.code} {e.reason}") from None
    status = result.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        raise RuntimeError(f"API query_status={status}")
    return result.get("data", [])


def rows_from_api(items: list) -> dict:
    rows = {}
    for it in items:
        sha256 = str(it.get("sha256_hash", "")).strip().lower()
        if not SHA256_RE.match(sha256):
            continue
        sig = str(it.get("signature") or "").strip()
        if not sig or sig.lower() in ("n/a", "na", "-"):
            sig = "Hash suspect non classifié (MalwareBazaar)"
        rows[sha256] = [
            str(it.get("first_seen", "")).strip(), sha256,
            _clean_hex(str(it.get("md5_hash", "")), 32),
            _clean_hex(str(it.get("sha1_hash", "")), 40),
            str(it.get("file_name") or "").strip(),
            str(it.get("file_type") or "").strip(), sig,
        ]
    return rows


def fetch_api_recent(key: str) -> dict:
    """Mode degrade : get_recent 'time' (60 min) + '100' (100 derniers). Documente
    par abuse.ch : seuls ces deux selecteurs existent."""
    items = []
    for selector in ("time", "100"):
        items += _api_post(key, selector)
    return rows_from_api(items)


def _clean_hex(value: str, length: int) -> str:
    value = (value or "").strip().lower()
    return value if HEX_RE[length].match(value) else ""


# Noms de colonnes (export abuse.ch) -> champ interne. Les positions par defaut
# servent seulement si aucun en-tete n'est trouve.
_NAMES = {
    "first_seen": ("first_seen_utc", "first_seen"),
    "sha256": ("sha256_hash", "sha256"),
    "md5": ("md5_hash", "md5"),
    "sha1": ("sha1_hash", "sha1"),
    "file_name": ("file_name",),
    "file_type": ("file_type_guess", "file_type"),
    "signature": ("signature",),
}
_DEFAULT_POS = {"first_seen": 0, "sha256": 1, "md5": 2, "sha1": 3,
                "file_name": 5, "file_type": 6, "signature": 8}


def _columns(header: list) -> dict:
    names = [h.strip().strip('"').lower() for h in header]
    pos = {}
    for field, aliases in _NAMES.items():
        for a in aliases:
            if a in names:
                pos[field] = names.index(a)
                break
    return pos if "sha256" in pos else dict(_DEFAULT_POS)


def parse_export(raw: bytes) -> dict:
    """Export MalwareBazaar (zip ou CSV brut) -> {sha256: ligne}. Les colonnes sont
    retrouvees par leur nom dans l'en-tete (commente ou non)."""
    if zipfile.is_zipfile(io.BytesIO(raw)):
        z = zipfile.ZipFile(io.BytesIO(raw))
        raw = z.read(z.namelist()[0])
    text = raw.decode("utf-8", errors="ignore")
    pos = dict(_DEFAULT_POS)
    data_lines = []
    for ln in text.splitlines():
        if not ln.strip():
            continue
        if ln.startswith("#"):
            if "sha256" in ln.lower():
                header = next(csv.reader([ln.lstrip("# ").strip()]), [])
                pos = _columns(header)
            continue
        data_lines.append(ln)
    rows = {}
    for parts in csv.reader(data_lines):
        if not parts:
            continue
        if parts[0].strip().lower().startswith("first_seen") or "sha256" in parts[0].lower():
            pos = _columns(parts)          # en-tete non commente
            continue
        need = max(pos.values())
        if len(parts) <= need:
            continue

        def col(field):
            i = pos.get(field)
            return parts[i].strip() if i is not None and i < len(parts) else ""

        sha256 = col("sha256").lower()
        if not SHA256_RE.match(sha256):
            continue
        sig = col("signature")
        if not sig or sig.lower() in ("n/a", "na", "-"):
            sig = "Hash suspect non classifié (MalwareBazaar)"
        rows[sha256] = [col("first_seen"), sha256,
                        _clean_hex(col("md5"), 32), _clean_hex(col("sha1"), 40),
                        col("file_name"), col("file_type"), sig]
    return rows


_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2})?")
_TOKEN_RE = re.compile(r"[0-9a-fA-F]{32,64}")


def parse_loose(raw: bytes) -> dict:
    """Secours si le format change : cherche sur chaque ligne un sha256 (64 hex),
    et si presents un md5 (32), un sha1 (40) et une date. Pas de nom ni de famille."""
    if zipfile.is_zipfile(io.BytesIO(raw)):
        z = zipfile.ZipFile(io.BytesIO(raw))
        raw = z.read(z.namelist()[0])
    text = raw.decode("utf-8", errors="ignore")
    rows = {}
    for ln in text.splitlines():
        if ln.startswith("#"):
            continue
        toks = {len(t): t.lower() for t in _TOKEN_RE.findall(ln) if len(t) in (32, 40, 64)}
        sha256 = toks.get(64, "")
        if not SHA256_RE.match(sha256):
            continue
        m = _DATE_RE.search(ln)
        first_seen = m.group(0).replace("T", " ") if m else ""
        rows[sha256] = [first_seen, sha256, toks.get(32, ""), toks.get(40, ""),
                        "", "", "Hash suspect non classifié (MalwareBazaar)"]
    return rows


def describe_raw(raw: bytes, key: str) -> str:
    """Apercu SANS la cle, pour diagnostiquer un format inattendu."""
    kind = "zip" if zipfile.is_zipfile(io.BytesIO(raw)) else "texte"
    if kind == "zip":
        z = zipfile.ZipFile(io.BytesIO(raw))
        raw = z.read(z.namelist()[0])
    head = raw[:400].decode("utf-8", errors="replace").replace(key, "***")
    return f"{kind}, {len(raw):,} octets ; debut : {head!r}"


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
        new = parse_export(open(a.export_file, "rb").read())
    else:
        key = os.environ.get("ABUSECH_KEY", "").strip()
        if not key:
            sys.exit("ERREUR : secret ABUSECH_KEY absent")
        new = {}
        try:
            raw = fetch_export(key)
            new = parse_export(raw)
            if len(new) < MIN_NEW_ROWS:
                print("AVERTISSEMENT : lecture structuree insuffisante "
                      f"({len(new)} lignes). Apercu de la reponse : {describe_raw(raw, key)}")
                loose_rows = parse_loose(raw)
                print(f"lecture tolerante : {len(loose_rows):,} hashes")
                if len(loose_rows) > len(new):
                    new = loose_rows
        except Exception as e:
            print(f"AVERTISSEMENT : export indisponible ({e})")
        if len(new) < MIN_NEW_ROWS:
            print("repli sur l'API get_recent (mode degrade)")
            try:
                api_rows = fetch_api_recent(key)
                print(f"API : {len(api_rows):,} hashes")
                if len(api_rows) > len(new):
                    new = api_rows
            except Exception as e2:
                print(f"AVERTISSEMENT : API indisponible ({e2})")

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
