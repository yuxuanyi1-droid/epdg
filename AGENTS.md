# Repository notes for agents

## What this repository is

An ePDG (SWu / VoWiFi gateway) control plane written in Go, plus the PyHSS
source tree. The Go control plane integrates four external components:

- **strongSwan** owns the SWu data plane. `internal/ipsec` drives it over the
  **VICI** protocol; `eap-radius` hands EAP-AKA to our RADIUS server.
- **PyHSS** (`pyhss/`) is the HSS/AuC and supplies AKA quintuplets over REST.
- **Open5GS** is the EPC peer, reached over **S2b (GTPv2-C)**.
- **Kamailio** carries IMS; P-CSCF discovery and the in-tunnel SIP path are ours.

## Build and test

```bash
go build ./...
go test ./...                 # protocol conformance, no external services needed
sudo -E SWAN=<prefix> test/integration/swu_eap_aka.sh   # real end to end test
```

## Things that cost time to discover

- **PyHSS vector endpoint.** `/auc/swm/eap_aka/plmn/<plmn>/imsi/<imsi>` returns
  only RAND/AUTN/XRES plus MAC/AK. EAP-AKA needs **CK and IK** to derive the MSK,
  so use `/auc/aka/vector_count/1/imsi/<imsi>`, which returns the full
  quintuplet. The SWm path also mangles the PLMN (`001001` comes back as
  `001100`); the AKA path does not.
- **PyHSS runtime deps.** `pip install -r pyhss/requirements.txt` fails on this
  image (`mysqlclient`, `pysctp`, `pyosmocom`). The API service only needs
  flask, flask-restx, werkzeug, requests, sqlalchemy, pycryptodome, pyyaml,
  redis, pydantic and prometheus_client. Redis is not required for the AKA
  endpoints.
- **strongSwan plugin packaging (Debian).** The `fips-prf` plugin lives in
  `libstrongswan-extra-plugins`; without it `eap-aka` silently loses its
  `EAP_SERVER:AKA` feature and EAP-AKA cannot be negotiated. The
  `eap-aka-3gpp` / `eap-aka-3gpp2` test cards used to drive a UE are **not
  packaged at all**, so a UE for the integration test has to be a source build:

  ```bash
  ./configure --prefix=/tmp/it/swan --sysconfdir=/tmp/it/swan/etc \
      --enable-eap-aka-3gpp --enable-eap-radius --enable-eap-aka \
      --enable-eap-identity --enable-vici --enable-swanctl \
      --enable-kernel-netlink --enable-openssl
  make -j4 && make install
  ```

- **VICI socket config is a URI.** `charon.plugins.vici.socket` must be
  `unix:///path/to/charon.vici`, not a bare path, otherwise charon logs
  "creating vici socket failed" and unloads the plugin.
- **swanctl argument order.** swanctl resets `optind = 2` after locating the
  command, so the command must be the first argument and everything else
  (`-u`, `--child`, ...) follows: `swanctl --list-sas -u unix:///run/charon.vici`.
- **swanctl does not auto-load `conf.d`.** `$SWANCTL_DIR/swanctl.conf` must exist
  and contain `include conf.d/*.conf`.
- **The classic `charon` hard codes `/run/charon.pid`.** Two instances on one
  host collide; remove the pid file before starting each instance.
- **`kernel-libipsec` needs `/dev/net/tun`.** In containers without it, set
  `charon.plugins.kernel-libipsec.load = no` or charon aborts at start up.
- **Requesting a virtual IP.** With `remote_ts = dynamic` on the responder and
  `pools` configured, charon answers `FAILED_CP_REQUIRED` unless the initiator
  sends a CFG_REQUEST, which means the client connection needs `vips = 0.0.0.0`.

## Protocol constants worth not re-deriving

- EAP-AKA AT_* types (RFC 4187 §11): RAND 1, AUTN 2, RES 3, AUTS 4, PADDING 6,
  NONCE_MT 7, PERMANENT_ID_REQ 10, MAC 11, NOTIFICATION 12, ANY_ID_REQ 13,
  IDENTITY 14, VERSION_LIST 15, SELECTED_VERSION 16, FULLAUTH_ID_REQ 17,
  COUNTER 19, COUNTER_TOO_SMALL 20, NONCE_S 21, CLIENT_ERROR_CODE 22,
  IV 129, ENCR_DATA 130, CHECKCODE 134.
- Subtypes: Challenge 1, Authentication-Reject 2, Synchronization-Failure 4,
  Identity 5, Notification 12, Reauthentication 13, Client-Error 14.
- Key hierarchy: `MK = SHA1(Identity|IK|CK)`, then the FIPS 186-2 SHA-1 PRF
  (compression function on a single zero-padded block, no Merkle-Damgard
  padding) for 1280 bits: `K_encr(16) | K_aut(16) | MSK(64) | EMSK(64)`.
  strongSwan's own test vector lives in
  `src/libstrongswan/plugins/fips_prf/fips_prf.c`.
- MSK delivery to strongSwan: `MS-MPPE-Recv-Key = MSK[0:32]`,
  `MS-MPPE-Send-Key = MSK[32:64]`; charon reassembles `recv || send`
  (`src/libradius/radius_socket.c`).
- RADIUS Message-Authenticator of a *reply* is HMAC-MD5 with the **Request**
  Authenticator in the header field, and the Response Authenticator is computed
  afterwards over the packet that already carries the Message-Authenticator.
