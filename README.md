# ePDG 控制面（Go 实现）

本仓库的主线是**基于 Go 实现的 ePDG 控制面**，配合以下四个既有组件形成完整链路：

| 组件 | 角色 | 与本仓库的关系 |
|------|------|----------------|
| **strongSwan** | SWu 数据面：IKEv2 / IPsec / EAP 中继 | 通过 **VICI 协议**驱动 charon；`eap-radius` 把 EAP-AKA 交给本仓库的 RADIUS 服务 |
| **PyHSS** | HSS / AuC：Milenage 算法与鉴权向量 | 原始代码树保留在 `pyhss/`，ePDG 通过其 REST API 取 AKA 五元组 |
| **Open5GS** | EPC：MME / HSS / PCRF / SGW / PGW | ePDG 通过 **S2b（GTPv2-C）** 与其 SGW-C/PGW-C 交互 |
| **Kamailio** | IMS：P-CSCF / I-CSCF / S-CSCF | ePDG 负责 P-CSCF 发现与隧道内的 SIP 通路 |

控制面语言由 Python 改为 Go。原因：重写后 ePDG 需要自己实现 **RADIUS + EAP-AKA（RFC 4187）**、
**GTPv2-C（TS 29.274）** 与 **VICI** 这几层协议，Go 在本仓库涉及的每个集成点上都有成熟且被
生产使用的协议库（strongSwan 官方 govici、wmnsk/go-gtp 等），同时具备静态类型与单二进制部署。

## 目录

```text
cmd/epdgd/            # 控制面入口
internal/eap/         # EAP（RFC 3748）与 EAP-AKA（RFC 4187），含 FIPS 186-2 PRF
internal/radius/      # RADIUS 编解码、Message-Authenticator、RFC 2548 MS-MPPE 密钥
internal/aaa/         # RADIUS EAP-AKA 服务端（对接 strongSwan eap-radius）
internal/hss/         # PyHSS REST 客户端（取 AKA 五元组）
internal/ipsec/       # strongSwan 驱动：VICI 后端 / swanctl 后端 / noop
internal/gtpv2/       # S2b GTPv2-C 消息（基于 go-gtp 编解码）
internal/s2b/         # S2b 会话生命周期适配
internal/session/     # 会话表
internal/server/      # HTTP 管理 API 与就绪检查
internal/compliance/  # 就绪检查框架
configs/              # ePDG / strongSwan / Kamailio / Open5GS / PyHSS 配置
database/             # 数据库备份与恢复脚本
docs/                 # 分模块文档
test/                 # 单元测试与真实环境联调脚本
pyhss/                # PyHSS 源码树（HSS / AAA 能力）
```

## 构建

```bash
go build ./...
go build -o epdgd ./cmd/epdgd
```

## 运行

```bash
./epdgd -config configs/epdg/epdg.yaml
```

开发配置（不连接 charon / PyHSS）：

```bash
./epdgd -config configs/epdg/epdg.dev.yaml
```

## AAA 链路

ePDG 自身就是 EAP-AKA 服务端，链路为：

```text
UE ──IKEv2/EAP-AKA──▶ strongSwan charon (responder, eap-radius)
                            │ RADIUS + EAP-Message
                            ▼
                     epdgd RADIUS EAP-AKA 服务端
                            │ GET /auc/aka/vector_count/1/imsi/<imsi>
                            ▼
                          PyHSS（Milenage 生成五元组）
```

要点：

- 使用 PyHSS 的 `/auc/aka/vector_count/1/imsi/<imsi>`，因为它返回**完整五元组**（含 CK/IK）。
  `/auc/swm/eap_aka/...` 只返回 RAND/AUTN/XRES，缺 CK/IK，无法推导 EAP-AKA 的 MSK。
- 密钥派生严格遵循 RFC 4187 §7：`MK = SHA1(Identity|IK|CK)`，
  `K_encr | K_aut | MSK | EMSK = PRF(MK, 1280)`，PRF 为 FIPS 186-2 附录 A 的 SHA-1 PRF
  （与 strongSwan 的 `PRF_FIPS_SHA1_160` 一致）。
- 成功后通过 **MS-MPPE-Recv-Key / MS-MPPE-Send-Key**（RFC 2548）把 MSK 交给 strongSwan，
  再由 charon 完成 IKE_AUTH 并安装 IPsec SA。

## API

- `GET  /healthz`
- `GET  /v1/sessions`
- `POST /v1/sessions/create`  `{"ue_id","imsi","apn"}`
- `POST /v1/sessions/delete`  `{"ue_id"}`
- `GET  /v1/compliance/check`

## 测试

### 协议一致性单元测试

使用 RFC / 3GPP 以及独立实现生成的已知答案向量，不需要任何外部服务：

```bash
go test ./...
```

覆盖内容：EAP-AKA 密钥派生（对齐 strongSwan 自身的 FIPS PRF 测试向量）、EAP-AKA
challenge 的逐字节编码、RADIUS Access-Challenge 的逐字节编码（与独立实现一致）、
RFC 2548 MS-MPPE 加密、GTPv2-C S2b 必需 IE 与响应解析、配置加载。

### SWu + EAP-AKA 真实联调

两个 strongSwan charon（ePDG 侧 `eap-radius`，UE 侧 `eap-aka-3gpp` 测试卡）+ 真实
PyHSS + 真实内核 XFRM，无 mock，**23/23 通过**：

```bash
sudo -E SWAN=/path/to/strongswan-prefix test/integration/swu_eap_aka.sh
```

断言：两端 IKE_SA `ESTABLISHED`、CHILD_SA `INSTALLED`、ePDG 从地址池分配内层地址、
隧道内 ICMP 可达、两端均安装真实 ESP 状态。

### S2b + Open5GS 真实联调

真实 Open5GS PGW-C（`open5gs-smfd`）+ 真实 PFCP 用户面（`open5gs-sgwud`），
无 mock，**18/18 通过**：

```bash
sudo -E OPEN5GS_BIN=/path/to/open5gs/bin OPEN5GS_PREFIX=/path/to/open5gs \
  test/integration/s2b_open5gs.sh
```

断言：PGW-C 接受 Create Session Request 并从自己的地址池分配 PDN 地址、返回 cause 16
与 C/U 面 F-TEID、Delete Session 正常释放；并以 PGW-C 自身发出的 S6b AAR/STR 与
Gx CCR-I/CCR-T 作为独立佐证。

该测试中 PCRF 与 3GPP AAA 由 `test/integration/diampeer` 充当测试替身——这两个
Diameter 对端不属于本仓库的交付范围，但 PGW-C 在没有它们时会拒绝建立会话。

### IMS REGISTER + Kamailio 真实联调

真实 P/I/S-CSCF（Kamailio，使用仓库内 `configs/kamailio/` 配置）+ 真实 PyHSS
（Cx：UAR/UAA、MAR/MAA、SAR/SAA），UE 用 Milenage 从 AKA nonce 推导 RES 回答
AKAv1-MD5 挑战，**19/19 通过**：

```bash
sudo -E PYHSS_PYTHON=/path/to/venv/bin/python test/integration/ims_register.sh
```

断言：401 挑战（AKAv1-MD5 + Security-Server）、S-CSCF 侧 AKA 响应校验通过、
HSS 产生 SAA、P-CSCF 记录 200 OK，且 200 OK 经**严格 IMS IPsec**回程送达 UE。

需要 MariaDB、Redis、Kamailio（含 IMS 模块）与带 PyHSS 依赖的 Python 环境。

### 尚未自动化覆盖

无。上述三个联调脚本覆盖 SWu/EAP-AKA、S2b 与 IMS REGISTER 三条链路。
