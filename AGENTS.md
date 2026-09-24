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

## S2b / Open5GS

- **Open5GS needs Diameter peers for S2b.** An S2b session is WLAN RAT type, and
  `smf_s5c_handle_create_session_request` refuses to proceed unless a Gx peer and
  an S6b peer are connected (`ogs_diam_is_relay_or_app_advertised`). There is no
  way to disable either at build time. `test/integration/diampeer` stands in for
  both; its CER must advertise Gx (16777238) and S6b (16777272) as
  Vendor-Specific-Application-Id groups with Vendor-Id 10415. Do **not**
  advertise Gy: that flips `smf_use_gy_iface()` to "enabled" and the SMF then
  requires an OCS.
- **The mandatory S2b information elements**, per Open5GS's own ePDG test harness
  (`tests/non3gpp/s2b-build.c`) and `smf_s5c_handle_create_session_request`:
  IMSI, Serving Network, RAT Type WLAN, Sender F-TEID C-plane (interface type 30),
  APN, Selection Mode, **PDN Address Allocation**, AMBR, and a Bearer Context
  containing EBI, Bearer QoS and the **ePDG S2b U-plane F-TEID** as instance 5
  (interface type 31). Omitting the PAA gives "No PAA"; omitting the U-plane
  F-TEID gives "No S2b ePDG GTP-U TEID".
- **Delete Session is addressed to the peer C-plane TEID.** The SMF resolves the
  session with `smf_sess_find_by_teid(gtp2_message.h.teid)`, so a request with
  TEID 0 is answered with cause 64 (Context Not Found). The ePDG has to keep the
  PGW C-plane TEID from the Create Session Response.
- **The PGW C-plane F-TEID is the instance 1 F-TEID** in the Create Session
  Response (`PGWS5S8FTEIDC`), and the PGW U-plane F-TEID lives in the bearer
  context with interface type 33 (S2b U PGW GTP-U).
- **`open5gs-upfd` cannot run without `/dev/net/tun`** (it opens `ogstun` for the
  session subnet, and `upf.session.subnet` is mandatory). `open5gs-sgwud` is a
  pure PFCP/GTP-U user plane with no subnet requirement and works as the PFCP
  peer instead, which is enough for the S2b control plane.
- **freeDiameter requires TLS material even for plain TCP peers**: omitting
  `TLS_Cred`/`TLS_CA` from the SMF's `smf.conf` aborts start up with "Missing
  private key configuration for TLS".
- **Diameter encoding rules that cost several iterations** (RFC 6733 and 3GPP
  TS 29.2xx): the AVP Length field excludes padding (so a parser must advance to
  the next 4-octet boundary), the command code is three octets with the
  Application-Id starting at octet 8, Host-IP-Address needs a two-octet Address
  family prefix, Vendor-Id is a base AVP without the V bit, Session-Id must be
  the first AVP (`RULE_FIXED_HEAD`) or the answer is dropped with "failed the
  dictionary / rules parsing", Auth-Request-Type is AVP 274 (AVP 1 is
  User-Name), and QoS-Class-Identifier is 4 octets inside a grouped ARP.

## IMS / Kamailio (work in progress)

The IMS side is not covered by an automated test yet. What is established and
what blocks it:

- Kamailio and every IMS module the P/I/S-CSCF configs need are packaged
  (`kamailio-ims-modules`, `kamailio-mysql-modules`, `kamailio-extra-modules`,
  `kamailio-presence-modules`, ...), and the IMS database from
  `database/kamailio/kamailio_ims.sql` restores cleanly into MariaDB.
- The three CSCFs need `mysql://<role>:heslo@127.0.0.1/<role>` users and a
  `/run/kamailio_<role>` directory for the `ctl` module's binrpc socket; without
  the directory `ctl` fails its `bind` and kamailio exits.
- `pcscf.cfg` listens on `10.255.0.1` and `10.46.0.1` from the original lab;
  `10.255.0.1` has to be repointed at whatever address the test topology uses.
- **Blocker: PyHSS's Cx handshake.** Kamailio's `cdp` connects to
  `hss.localdomain:3868` but PyHSS's `diameterService.py` closes the connection
  instead of answering the CER. Two things are needed for it: Redis must be
  running (without it the service dies in `writeOutboundData` with an
  `IndexError` from the Redis client), and even with Redis the CER is still not
  answered. Until Cx works the S-CSCF cannot fetch AKA vectors (`ims_auth` MAR),
  so no 401 challenge can be produced and the IMS REGISTER flow cannot be
  tested end to end.

### Building Open5GS for the S2b test

```bash
apt install -y meson ninja-build build-essential pkg-config libssl-dev \
    libgcrypt20-dev libsctp-dev libyaml-dev libcurl4-openssl-dev \
    libtalloc-dev libmongoc-dev libmicrohttpd-dev libidn11-dev cmake
git clone --depth 1 https://github.com/open5gs/open5gs
cd open5gs
meson setup build --prefix=/tmp/it/o5gs -Dbuildtype=debug
ninja -C build && ninja -C build install
```

### Building strongSwan for the SWu test

Debian does not package the `eap-aka-3gpp` test card, so a UE that can compute
AKA vectors requires a source build:

```bash
./configure --prefix=/tmp/it/swan --sysconfdir=/tmp/it/swan/etc \
    --enable-eap-aka-3gpp --enable-eap-radius --enable-eap-aka \
    --enable-eap-identity --enable-vici --enable-swanctl \
    --enable-kernel-netlink --enable-openssl
make -j4 && make install
```

