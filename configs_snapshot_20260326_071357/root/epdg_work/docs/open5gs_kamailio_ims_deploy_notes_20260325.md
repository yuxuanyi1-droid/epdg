# Open5GS + Kamailio IMS + PyHSS 部署说明与踩坑记录（2026-03-25）

## 1. 部署目标与当前状态

- OS: Ubuntu 22
- Open5GS: EPC 模式（MME/SMF/UPF），`open5gs-hssd` 已停用
- HSS: 使用 `PyHSS` 替代 Open5GS HSS
- IMS Core: Kamailio P-CSCF / I-CSCF / S-CSCF 同机部署（源码编译模块）
- IMS 业务目标: VoLTE/IMS 注册链路可走通（协议链路：SIP + Cx）

当前已确认：
- Diameter Peer 正常：`mme.localdomain`、`icscf.localdomain`、`scscf.localdomain`
- Cx 鉴权链路正常：可见 `UAR/UAA`、`MAR/MAA`
- P-CSCF 保持标准 IPsec 行为：无 UE 安全协商时返回 `503 Service Unavailable (Create ipsec failed)`

---

## 2. 关键配置概览（当前生效）

### 2.1 PyHSS

- 配置文件：`/etc/pyhss/config.yaml`
- 核心参数：
  - `OriginHost: hss.localdomain`
  - `OriginRealm: localdomain`
  - `bind_ip: ["127.0.0.8"]`
  - `bind_port: 3868`
  - `scscf_pool:`
    - `sip:10.46.0.2:5062`

### 2.2 Kamailio IMS

- P-CSCF: `/etc/kamailio_pcscf`
  - `listen=udp:10.46.0.2:5060`
  - `WITH_IPSEC` 开启
  - IPsec 端口：`6062/6063`
- I-CSCF: `/etc/kamailio_icscf`
  - `listen=udp:10.46.0.2:5061`
  - `DB_URL="mysql://icscf:heslo@127.0.0.1/icscf"`
- S-CSCF: `/etc/kamailio_scscf`
  - `listen=udp:10.46.0.2:5062`

### 2.3 Open5GS

- `mme/smf/upf` 运行正常
- HSS 对接 PyHSS（Diameter 到 `hss.localdomain`）
- `ogstun` 已用于 IMS 网段（P-CSCF 可达地址 `10.46.0.2`）

---

## 3. 关键坑点与修复结论

### 坑 1：PyHSS 下发的 S-CSCF 地址是裸域名，I-CSCF 转发失败

现象：
- I-CSCF 报错：`bad_uri: [scscf.ims.mnc001.mcc001.3gppnetwork.org]`
- 终端侧表现：P-CSCF 返回 `504 Server Time-Out`

根因：
- PyHSS `scscf_pool` 返回非 SIP URI，且域名在当前环境不可解析。

修复：
- 将 `scscf_pool` 改为可路由 SIP URI：`sip:10.46.0.2:5062`

---

### 坑 2：P-CSCF IPsec 端口与 S-CSCF 监听冲突

现象：
- P-CSCF/S-CSCF 同机时端口冲突或注册链路异常。

修复：
- P-CSCF IPsec 改到 `6062/6063`，避免占用 S-CSCF `5062`。

---

### 坑 3：I-CSCF DB URL 写法错误导致模块初始化失败

现象：
- I-CSCF 初始化报数据库绑定错误。

修复：
- `DB_URL` 使用标准格式：
  - `mysql://icscf:heslo@127.0.0.1/icscf`

---

### 坑 4：`/etc/hosts` 与运行时解析不一致

现象：
- Kamailio 进程在某些阶段无法解析 `scscf.localdomain`。

建议：
- 同机实验环境优先使用可直达 IP（例如 `sip:10.46.0.2:5062`）避免解析不确定性。
- 保留 `/etc/hosts` 静态映射用于运维排障。

---

### 坑 5：用裸 SIP 工具无法验证“标准 IMS/IPsec 成功注册”

说明：
- `sipp/python socket` 可验证 SIP 与 Cx 交互，但无法替代标准 UE 的 IMS AKA + IPsec 协商。
- 看到 `503 Create ipsec failed` 是标准行为（无安全协商参数）。

结论：
- 若要“完全按协议”验收，必须用支持 IMS/IPsec 的 UE（真机+ISIM 或商用UE模拟器）。

---

## 4. 运维检查命令（常用）

```bash
# 核心服务状态
systemctl status pyhss_hss pyhss_diameter open5gs-mmed open5gs-smfd open5gs-upfd

# Diameter 监听
ss -ltnp | rg ':3868|:3869|:3870'

# SIP 监听
ss -lunp | rg '5060|5061|5062|6062|6063'

# 关键日志（SIP + Cx）
rg -n "REGISTER|UAR|UAA|MAR|MAA|Create ipsec failed" /var/log/syslog | tail -n 200

# PyHSS peers
python3 - <<'PY'
import redis
r=redis.Redis(host='localhost',port=6379,decode_responses=True)
print(r.hgetall('hss.localdomain:diameter:diameterPeers'))
PY
```

---

## 5. 当前验收结论

- 已达成：
  - Open5GS EPC 与 PyHSS 对接稳定
  - Kamailio IMS 三节点与 PyHSS Cx 接通
  - `UAR/UAA`、`MAR/MAA` 正常
  - P-CSCF 标准 IPsec 拦截行为恢复

- 未在本机“纯脚本UE”达成：
  - IMS/IPsec 完整成功注册（200 OK）

原因：
- 缺少支持 IMS AKA + IPsec 的真实 UE 能力。

