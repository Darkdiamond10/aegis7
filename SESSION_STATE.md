# Session State

## Current Status
All identified issues in the C2 communications layer have been fixed. The framework is ready for build verification.

### Fixes Applied

**Buffer Overflow Fixes (Session 1):**
1. `AEGIS_C2_MAX_PAYLOAD_SIZE` bumped to 25 MB in `common/config.h`
2. `+ EVP_MAX_BLOCK_LENGTH` padding on 3 decryption `malloc` sites in `c2_comms/c2_client.c`
3. `#include <openssl/evp.h>` added to `c2_client.c`

**Communications Audit Fixes (Session 2):**
4. `crypto.c` — deterministic `0xAA` HKDF salt matching `server_crypto.py`
5. `server_crypto.py` — added `_maybe_rekey()` for rolling key derivation (forward secrecy)
6. `c2_client.c` — `payload_len` bounds validation in `beacon`, `fetch_stage`, `fetch_resource`
7. `c2_client.c` — 25 MB stack buffer → heap `malloc` in `aegis_c2_beacon()`
8. `c2_client.c` — all 4 `tls_send` return values checked
9. `c2_client.c` — `SO_RCVTIMEO` 30s timeout on all TLS sockets
10. `server.py` — `_handle_resource_req` now encrypts response with AES-GCM envelope
11. `c2_client.c` — deprecated OpenSSL init → `OPENSSL_init_ssl(0, NULL)`

## Blocker/Error
**NONE.** All known issues resolved.

## Next Steps
1. Install build prerequisites on Linux/WSL (`build-essential`, `libssl-dev`, `musl-tools`)
2. Recompile: `make clean && make stager MODE=debug`
3. Verify end-to-end: stager → C2 server → ghost_loader decryption → memfd exec
