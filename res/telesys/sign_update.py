#!/usr/bin/env python3
"""Telesys: metadados assinados da atualização automática (src/updater/telesys.rs).

Uso no workflow (job telesys-update-metadata do flutter-build.yml):

    python3 res/telesys/sign_update.py --update-json res/telesys/update.json \
        --version 1.5.3 --repo owner/repo --tag build-<uid> --dir ./artifacts \
        --out-metadata telesys-update.json --out-signature telesys-update.json.sig

A chave privada vem de TELESYS_UPDATE_ED25519_SEED (base64 de 32 bytes). Assina
`b"Telesys update metadata v1\\n" + bytes do JSON`; o .sig é o base64 da assinatura.
Só entram os .exe do Windows (o cliente personalizado sempre atualiza pelo .exe).
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys

from nacl.signing import SigningKey

CONTEXT = b"Telesys update metadata v1\n"
APP = "suporte-telesys"
# arquivo da release -> (plataforma, arquitetura, formato) do cliente
PATTERNS = [
    (re.compile(r"^rustdesk-[0-9.]+-x86_64\.exe$"), ("windows", "x86_64", "exe")),
    (re.compile(r"^rustdesk-[0-9.]+-aarch64\.exe$"), ("windows", "aarch64", "exe")),
    (re.compile(r"^rustdesk-[0-9.]+-x86-sciter\.exe$"), ("windows", "x86", "exe")),
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--update-json", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--dir", required=True)
    p.add_argument("--out-metadata", required=True)
    p.add_argument("--out-signature", required=True)
    a = p.parse_args()

    with open(a.update_json, encoding="utf-8") as f:
        info = json.load(f)
    channel = str(info.get("channel", ""))
    build = int(info.get("build", 0))
    if not re.fullmatch(r"[a-z0-9-]{1,32}", channel) or build <= 0:
        sys.exit("update.json sem linha/build válidos")

    artifacts = []
    for name in sorted(os.listdir(a.dir)):
        for pattern, (platform, arch, fmt) in PATTERNS:
            if pattern.match(name):
                path = os.path.join(a.dir, name)
                artifacts.append({
                    "platform": platform,
                    "arch": arch,
                    "format": fmt,
                    "url": f"https://github.com/{a.repo}/releases/download/{a.tag}/{name}",
                    "file_name": name,
                    "size": os.path.getsize(path),
                    "sha256": sha256(path),
                })
    if not artifacts:
        sys.exit("nenhum instalador .exe do Windows encontrado")

    metadata = {
        "schema_version": 1,
        "app": APP,
        "channel": channel,
        "build": build,
        "version": a.version,
        "release_id": a.tag,
        "artifacts": artifacts,
    }
    data = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode()

    seed = base64.b64decode(os.environ["TELESYS_UPDATE_ED25519_SEED"].strip())
    if len(seed) != 32:
        sys.exit("TELESYS_UPDATE_ED25519_SEED precisa ter 32 bytes")
    key = SigningKey(seed)
    signature = key.sign(CONTEXT + data).signature
    key.verify_key.verify(CONTEXT + data, signature)

    with open(a.out_metadata, "wb") as f:
        f.write(data)
    with open(a.out_signature, "w", encoding="ascii") as f:
        f.write(base64.b64encode(signature).decode())
    print(f"linha {channel}, build {build}, chave pública "
          f"{base64.b64encode(bytes(key.verify_key)).decode()}")
    for x in artifacts:
        print(f"  {x['arch']:8} {x['file_name']} {x['size']} {x['sha256']}")


if __name__ == "__main__":
    main()
