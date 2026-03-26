# Ubuntu 22.04：Open5GS EPC + Kamailio IMS + PyHSS（VoLTE）

这份文档面向“同机部署、用 Open5GS 做 EPC，Kamailio 做 IMS，PyHSS 做 IMS HSS”的最小可跑通方案。

## 0. 关键结论（避免走弯路）

- **PyHSS 不能替代 Open5GS 的 HSS 用于 EPC/LTE Attach**：Open5GS EPC 的 HSS 接口/数据模型与 IMS 的 Cx/Sh(Diameter) 不同；EPC 侧鉴权、位置更新等流程必须由 Open5GS HSS（MongoDB）完成。
- 可行架构是 **“双 HSS”**：
  - `Open5GS-HSS(MongoDB)`：负责 LTE Attach / EPC 会话侧用户数据（IMSI/Ki/OPc/APN 等）。
  - `PyHSS(MySQL/MariaDB)`：负责 IMS（IMPI/IMPU、Cx 鉴权等）。
- 如果你希望“单一来源数据”，做法通常是写一个**同步脚本**：从 PyHSS（或你的统一表）同步出 `IMSI/Ki/OPc/APN` 到 Open5GS MongoDB（或通过 Open5GS WebUI/DB 工具导入）。

## 1. 网络规划（建议值）

同机部署时，建议用 Open5GS 的 `ogstun` 作为 UE 数据出口，并给 IMS 分配一个“UE 侧可达”的 P-CSCF 地址：

- `APN internet`：`10.45.0.0/16`（UE 上网用，可选）
- `APN ims`：`10.46.0.0/16`（UE 访问 P-CSCF/IMS 用）
- `P-CSCF` 绑定地址：`10.46.0.2`（加到 `ogstun` 上）
- 本地 DNS（给 UE 下发）：`10.46.0.1`（dnsmasq 监听在 `ogstun` 上）

说明：`ogstun` 是 TUN 设备；把 `10.46.0.2/32` 配到 `ogstun` 后，UE 走 IMS APN 时即可直达同机 Kamailio。

## 2. 安装与启用 Open5GS（EPC）

安装：

```bash
sudo apt update
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:open5gs/latest
sudo apt update
sudo apt install -y open5gs
sudo systemctl enable --now mongod
sudo systemctl enable --now open5gs-mmed open5gs-sgwcd open5gs-sgwud open5gs-pgwd open5gs-hssd
```

初始化/创建订阅用户（示例，参数按你 SIM/USIM 实际填写）：

```bash
sudo open5gs-dbctl add 001010000000001 00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff
```

> `open5gs-dbctl add <IMSI> <Ki> <OPc>`：Ki/OPc 需要与你 SIM 卡一致；很多教程用测试卡参数。

### 2.1 配置 PGW：增加 IMS APN 池、下发 DNS

编辑 `/etc/open5gs/pgw.yaml`，至少确认：

- `gtpu` 绑定到你的实际网卡地址（同机无所谓，但建议显式设置）
- `session:` 里有 `apn: ims` 对应的 `subnet`
- `dns:` 指向 `10.46.0.1`（本机 dnsmasq）

概念示例（字段名以你当前 open5gs 版本为准，实际以 `/etc/open5gs/pgw.yaml` 为准）：

```yaml
session:
  - apn: ims
    subnet: 10.46.0.0/16
    dns:
      - 10.46.0.1
```

重启：
```bash
sudo systemctl restart open5gs-pgwd
```

### 2.2 给 `ogstun` 增加 P-CSCF/DNS 地址

先启动 Open5GS PGW 后再执行（否则 `ogstun` 不存在）：

```bash
sudo ip addr add 10.46.0.1/32 dev ogstun || true
sudo ip addr add 10.46.0.2/32 dev ogstun || true
```

建议做成 systemd drop-in（可选）：在 `open5gs-pgwd` 启动后自动加 IP。

## 3. dnsmasq：给 UE 提供 IMS 域解析（可随时改 PLMN）

安装：
```bash
sudo apt install -y dnsmasq
```

新增配置 `/etc/dnsmasq.d/ims.conf`（示例用 “通配 PLMN” 的思路：你以后改 MCC/MNC 也不需要改 DNS 服务器本身，只要维护一份 zone/记录）：

```conf
interface=ogstun
bind-interfaces
listen-address=10.46.0.1

# 你自定义的 IMS 域（推荐）：ims.test
address=/ims.test/10.46.0.2

# 如果你要玩 3GPP 域名（随便换 PLMN），常见模式：
# ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org
# dnsmasq 不擅长自动生成 NAPTR/SRV，这里用最简 A 记录先让 UE 能打到 P-CSCF。
# 你可以在实验时把 UE 的 P-CSCF 发现改成“手动指定”，或用完整 DNS 服务器（bind9/unbound）做 NAPTR/SRV。
```

重启：
```bash
sudo systemctl restart dnsmasq
sudo systemctl enable dnsmasq
```

> 真实 VoLTE/IMS 终端更偏好 NAPTR/SRV（RFC/3GPP），如果你的 UE 强依赖 NAPTR/SRV，建议用 bind9 做 zone（Kamailio 源码里也有示例 zone 文件）。

## 4. Kamailio：用官方 IMS 示例配置起 P-/I-/S-CSCF

你当前工作区已包含 Kamailio 源码（`kamailio/`），里面自带 IMS 示例：

- `kamailio/misc/examples/ims/pcscf`
- `kamailio/misc/examples/ims/icscf`
- `kamailio/misc/examples/ims/scscf`

### 4.1 编译安装（启用 IMS 常用模块）

最简单做法是按示例编译并安装到 `/usr/local`（你已有 `start_ims.sh` 默认也是这个路径）：

```bash
cd kamailio
make cfg
make -j"$(nproc)" all
sudo make install
```

### 4.2 放置配置文件

将示例 cfg 放到 `/etc/kamailio/`，并按你的地址修改以下关键参数：

- P-CSCF 监听：`10.46.0.2:5060`（来自 IMS APN）
- I-/S-CSCF 监听：可用 `127.0.0.1` 或本机管理网
- 域名：先用 `ims.test`（后续你改 PLMN 时，只要 DNS 与 Kamailio domain 同步改即可）
- Diameter（到 PyHSS）连接参数：主机/realm/port

你可以从 `.cfg.sample` 开始：

```bash
sudo mkdir -p /etc/kamailio
sudo cp kamailio/misc/examples/ims/pcscf/pcscf.cfg.sample /etc/kamailio/pcscf.cfg
sudo cp kamailio/misc/examples/ims/icscf/icscf.cfg.sample /etc/kamailio/icscf.cfg
sudo cp kamailio/misc/examples/ims/scscf/scscf.cfg.sample /etc/kamailio/scscf.cfg
```

然后用你的 `start_ims.sh` 拉起三进程（你工作区已有该脚本）：
```bash
sudo ./start_ims.sh
```

## 5. PyHSS：作为 IMS HSS（Cx/Diameter）

你工作区已有 `pyhss/`。典型部署方式是用它自带的 docker compose 或本机 python 方式跑起来，并准备 MySQL/MariaDB。

关键目标：

- PyHSS 的 Diameter（Cx）可被 S-CSCF/I-CSCF 访问（同机一般是 `127.0.0.1`）
- PyHSS 内配置的 `realm`/`host` 与 Kamailio 的 ims_diameter 配置一致
- 在 PyHSS 中创建 IMS 用户（IMPI/IMPU/密码或 AKA 参数）与你 UE 的 ISIM/IMS 配置一致

> 注意：IMS AKA 的参数（例如 OPc、K、AMF、SQN 等）与 LTE USIM 那套相关但不等同；你需要确保 UE 的 ISIM/IMS 参数与 PyHSS 一致。

## 6. 让 UE 真正“走 VoLTE”的常见额外项（强烈建议）

- **RTPengine**：媒体中继（解决 NAT/对称 RTP/单通等问题）
- **QoS/PCF/PCRF**：严格 VoLTE 可能需要（实验环境可先不做或弱化）
- **短信/语音业务平台**：IMS 只提供控制面，呼叫还需要对端/应用服务器（AS）或至少能互打的 SIP 用户

## 7. 最小验证路径（建议顺序）

1. LTE Attach + 建立 `ims` APN（看 PGW 日志是否分配 `10.46.x.x`）
2. UE 通过 `ims` APN 能 `ping 10.46.0.2`（P-CSCF 地址）
3. UE 发起 IMS REGISTER，P-CSCF 收到 SIP（Kamailio 日志能看到）
4. Kamailio 通过 Diameter Cx 访问 PyHSS（PyHSS 日志有 Cx 事务）
5. 注册成功后，再做 SIP 呼叫并看 RTPengine 是否有会话

---

如果你愿意我继续往下做“可复制的落地配置”，我需要你给出：

- 你的无线侧（eNB/gNB）用的是 `srsRAN`/`OpenAirInterface`/商用 eNB？（影响 MME S1AP 绑定、TAC、PLMN）
- 你准备使用的测试卡参数：`IMSI/Ki/OPc`（EPC）以及 IMS（ISIM/IMPI/IMPU）参数
- 你希望的“可随意切 PLMN”策略：是更换 MCC/MNC 还是同时换 IMS realm/域名？

