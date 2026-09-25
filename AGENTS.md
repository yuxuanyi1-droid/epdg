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

## IMS / Kamailio

Covered by `test/integration/ims_register.sh`: the full `401 -> 200 OK` REGISTER
with real P/I/S-CSCF, real PyHSS over Cx, and a UE that answers the AKAv1-MD5
challenge with RES derived through Milenage. Environment notes:

- Kamailio and every IMS module the P/I/S-CSCF configs need are packaged
  (`kamailio-ims-modules`, `kamailio-mysql-modules`, `kamailio-extra-modules`,
  `kamailio-presence-modules`, ...), and the IMS database from
  `database/kamailio/kamailio_ims.sql` restores cleanly into MariaDB.
- The three CSCFs need `mysql://<role>:heslo@127.0.0.1/<role>` users and a
  `/run/kamailio_<role>` directory for the `ctl` module's binrpc socket; without
  the directory `ctl` fails its `bind` and kamailio exits.
- `pcscf.cfg` listens on `10.255.0.1` and `10.46.0.1` from the original lab. The
  test provides them on a dummy interface (`ims-lab0`) instead of editing the
  shipped config.
- **A SIGKILLed kamailio leaves its pid file behind**, and the next start aborts
  with `daemonize(): running process found in the pid file`. Kill the processes
  and remove `/run/kamailio_<role>/*.pid` before restarting.
- The P-CSCF logs rtpengine connection failures while starting (rtpengine is not
  needed for REGISTER) and only begins serving SIP once that settles, so probe it
  with a throwaway REGISTER rather than relying on a fixed sleep.
- **The IMS domain and the IMSI disagree on MNC width.** The I-CSCF/S-CSCF configs
  and the subscriber's IMPU use `ims.mnc001.mcc001.3gppnetwork.org` (three digit),
  while the IMSI `001010000000001` and PyHSS's `hss.MNC` carry the two digit form
  `01`. Building the realm as `mnc${MCC}${MNC}` yields `mnc00101` and the
  registration fails; keep the two spellings separate.
- **Strict IMS IPsec changes the return path.** With `STRICT_IMS_IPSEC` the
  P-CSCF delivers the final response through `ims_ipsec_pcscf`'s
  `ipsec_forward()` to the port the UE advertised as `port-s` in
  Security-Client, not back to the source port. A test UE must listen on that
  port as well, otherwise the 200 OK is produced and then lost.
- **Blocker (SOLVED, and my earlier diagnosis was wrong).** The Cx interface was
  never a PyHSS protocol bug. Two operational mistakes made it look like one:
  1. PyHSS runs as **two** services. `diameterService.py` is only a socket relay:
     it reads raw bytes into the Redis list `diameter-inbound` and writes raw
     bytes from `diameter-outbound-<ip>-<port>`. The Diameter logic - including
     answering the CER with a CEA - lives in `hssService.py`, which consumes
     `diameter-inbound`, calls `Diameter.generateDiameterResponse()` and pushes
     the reply onto `diameter-outbound-<ip>-<port>`. Starting only
     `diameterService.py` leaves the CER unanswered forever (Kamailio cdp logs
     "connected" then "read on socket returned 0 ... dropping").
  2. `diameter.py` loads its iFC/Sh templates through
     `jinja2.FileSystemLoader(searchpath="../")`, a path **relative to the
     working directory**. The packaged systemd units run with
     `WorkingDirectory=/etc/pyhss/services/`, so `../default_ifc.xml` resolves to
     `/etc/pyhss/default_ifc.xml`. Run `hssService.py` from anywhere else and the
     SAR handler dies with
     `jinja2.exceptions.TemplateNotFound: 'default_ifc.xml' not found in search
     path: '../'`, which surfaces at the S-CSCF as
     `ims_registrar_scscf: async_cdp_callback(): Transaction timeout - did not
     get SAA` and then a 504 towards the UE. Always start the services with
     `cd pyhss/services` first.
- Redis is mandatory for both PyHSS services; without it `hssService.py` cannot
  read `diameter-inbound` and `diameterService.py` dies in `writeOutboundData`
  with `IndexError: string index out of range`.
- **Verified**: with both services started from `pyhss/services/`, Cx reaches
  `State: I_Open` on the I-CSCF and S-CSCF (`kamcmd -s
  unix:/run/kamailio_<role>/kamailio_ctl cdp.list_peers`) and the full
  `401 -> 200 OK` REGISTER completes.

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

## Containerised lab (deploy/)

`deploy/lab.yaml` is the single source of truth; `cmd/labctl` turns it into
`deploy/.env` plus `deploy/runtime/`, and serves the configuration UI.

- **Render is copy-and-substitute, not re-authoring.** The shipped configs under
  `configs/` are copied and then rewritten by an explicit substitution table
  (`internal/lab/render_services.go`). Every left-hand side is a string that
  really exists in `configs/`, so a change there fails the render loudly instead
  of silently emitting a wrong address. New parameters must be added to the
  table anyway, or the UI would accept edits that never reach the containers -
  that bit `open5gs.mme.*` once.
- **Containers cannot share a static IP.** PyHSS is three processes that must
  answer on one address, so they run in a single container with a small
  supervisor in the entrypoint. Three compose services with the same
  `ipv4_address` fail with "Address already in use".
- **Kamailio needs `shm_size`.** `mlock_pages`/`shm_force_alloc` pre-fault the
  whole shared memory pool; with the Docker default of 64 MB the registrar path
  dies. The P-CSCF config also carries those two options, so the renderer turns
  both off for containers.
- **MariaDB init scripts only run on a fresh data directory.** They stay in
  `/docker-entrypoint-initdb.d` for the schema and the CSCF users, which means
  changing `credentials.kamailio_db_password` needs `docker compose down -v`.
  The init SQL is generated from `lab.yaml` so the password is not duplicated.
- **freeDiameter requires TLS material** even when every peer is `No_TLS`, so the
  Open5GS image generates a self-signed pair at `/etc/open5gs/tls`.
- **Open5GS's UPF needs `/dev/net/tun` and `NET_ADMIN`**; without the device it
  will not start. SGW-U (`open5gs-sgwud`) is a pure PFCP/GTP-U user plane with no
  TUN requirement and covers the S2b control-plane tests.
- The compose file declares static IPs from `deploy/.env`, and `extra_hosts`
  maps `hss.localdomain` to the PyHSS container so Kamailio's cdp and
  freeDiameter can resolve it.

### Container Kamailio version (was misdiagnosed as a config bug)

The containerised S-CSCF used to segfault on the first registration, inside the
lab's modified branch in `configs/kamailio/scscf/kamailio.cfg`:

```
if (!impu_registered("location")) { xlog("L_ERR", "Not REGISTERED"); save("PRE_REG_SAR_REPLY", "location"); }
```

From the UE this looked like a protocol failure - the 401 challenge arrived and
then a 504 came back instead of a 200 OK - and since nothing reached the HSS it
read as a Cx problem. Neither was true.

The cause was the base image: `debian:bookworm-slim` ships **Kamailio 5.6.3**,
whose `ims_registrar_scscf` crashes in `save()` before sending any Diameter
request, while the configs were written and validated against the **6.0.1** in
trixie. Building the image on `debian:trixie-slim` fixes it, and the containerised
REGISTER now completes 401 -> 200 OK (17/17 in `deploy/scripts/verify.sh`,
including an explicit assertion that no SIGSEGV was logged).

Ruled out along the way, so they do not need retesting: shared memory
(`shm_size`), `mlock_pages`/`shm_force_alloc`, `ims_usrloc_scscf.db_mode` and the
database account. The `#!define URI` self-name *was* a separate real bug: the
renderer rewrote `listen=` but left the node's own URI on 127.0.0.1, so
`ims_auth.name` and `registrar.scscf_name` described an address the node did not
have.

### Building the images

The Open5GS image is built from source and needs the full freeDiameter toolchain;
`flex` and `bison` are easy to miss and fail the build at
`subprojects/freeDiameter/meson.build`.

### Container EPC gotchas

Found while making an S2b session complete inside the container lab. Each one
presents as a protocol rejection from the peer, so they are worth knowing:

- **PyHSS has no S6b.** Its Diameter applications are Cx (16777216), Sh
  (16777217), Rx (16777236), Gx (16777238), S6a (16777251), EIR (16777252) and
  16777291. An S2b (WLAN) session makes Open5GS's PGW-C send **both** a Gx CCR
  and an S6b AAR, and it refuses the session outright (cause 100) if either has
  no answering peer. The repository's `test/integration/diampeer` fills both
  roles; the lab runs it as the `aaa` service. Without it, S2b cannot complete
  against PyHSS no matter how correct the ePDG's request is.
- **freeDiameter's `ConnectPeer` name must equal the peer's Origin-Host.** Naming
  the peer `hss.localdomain` while it identifies as `aaa.localdomain` makes
  freeDiameter reject the CEA with `save_remote_CE_info: Invalid argument`, and
  the peer never reaches OPEN. The symptom is "No Gx Diameter Peer" from the SMF,
  which points at the wrong layer entirely.
- **The PGW-C needs a PFCP peer.** With `upf` in its own profile (it needs
  `/dev/net/tun`), the SMF has nobody to establish the session with. Pointing its
  PFCP client at the SGW-U, which is a pure PFCP/GTP-U function, fixes it.
- **freeDiameter validates its own TLS certificate against its DiameterIdentity**,
  so one certificate has to carry a subjectAltName for every identity in the lab
  (mme/smf/hss/pcrf.localdomain).
- **Open5GS's runtime image needs more than the binaries**: `libogs*`, `libfd*`,
  the freeDiameter `.fdx` extensions and `libprom.so` (which lands in the
  multiarch lib directory). Missing any of them makes every daemon exit 127 with
  "error while loading shared libraries".

### VICI details that cost time

- **There is no `load-all` VICI command.** charon answers it with pktCmdUnkown
  (packet type 2), which govici reports as "unexpected response type: 2".
  swanctl's `--load-all` issues `load-creds`, `load-authorities`, `load-pools`
  and `load-conns` separately.
- **Do not subscribe to an event for those commands.** Adding a `control-log`
  subscription before them fails against this charon, and the failure surfaces as
  the same "unexpected response type: 2", which makes it look like the command
  name is wrong when it is the subscription.
- The ePDG therefore does **not** reload charon's configuration while accepting a
  session: in passive mode the connection already exists in charon, and loading
  the configuration is charon's own lifecycle. `Load()` is attempted once at
  start up and only logged if it fails.
- **CHILD_SA termination has to be idempotent.** A pending session has no
  CHILD_SA yet, and charon answers "no matching SAs to terminate found"; treating
  that as an error stops the S2b session from being released.

### Host strongSwan

- `strongswan-charon` (not `charon-systemd`) provides the standalone
  `/usr/lib/ipsec/charon`. The systemd variant exits silently without the notify
  socket and leaves no VICI socket.
- `kernel-libipsec` aborts charon when `/dev/net/tun` is absent, so the generated
  `strongswan.conf` sets `load = no` for it and keeps `kernel-netlink`.
- The VICI socket lives in `/run/epdg-lab/`, a directory shared with the ePDG
  container. Binding `/run/charon.vici` directly does not work: a bind mount
  whose source does not exist yet is created as a *directory* by the container
  runtime, and charon then cannot create its socket there.
