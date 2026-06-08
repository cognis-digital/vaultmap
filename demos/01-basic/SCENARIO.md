# VAULTMAP Demo 01 - Basic estate inventory

This demo shows building an encrypted personal asset inventory suitable for an
executor or trustee, then producing an estate-readiness rollup.

## Why VAULTMAP

When someone passes away (or is incapacitated), heirs often cannot find the
accounts, let alone the credentials. VAULTMAP keeps a single, encrypted,
standard-library-only inventory of every account/asset plus *where the
credentials live* and *who the beneficiary is* -- the two facts an executor
actually needs.

Encryption: PBKDF2-HMAC-SHA256 key derivation (200k iterations) + an
HMAC-SHA256 CTR stream cipher with encrypt-then-MAC authentication. No third
party libraries, no network, no cloud.

## Run it

```bash
export VAULTMAP_PASSWORD='correct horse battery staple'
VAULT=./estate.vault

# 1. create the encrypted vault
python -m vaultmap init "$VAULT"

# 2. import the sample entries (one add per line)
while IFS= read -r line; do
  [ -z "$line" ] && continue
  python -m vaultmap add "$VAULT" $line
done < demos/01-basic/entries.txt

# 3. estate-planning rollup: net worth + readiness + gaps
python -m vaultmap --format json summary "$VAULT"
```

## What to look for

- `net_worth` nets liabilities (the mortgage) against assets.
- `readiness_pct` measures how many entries have institution + beneficiary +
  credential location filled in -- your executor checklist.
- `missing_beneficiary` / `missing_location` list the records that still need
  attention (the crypto wallet here is intentionally incomplete).

The vault file on disk is fully encrypted; opening it without the password
(or after tampering) fails MAC verification and exits non-zero.

`entries.txt` holds the realistic sample inventory used above.
