# VoWiFi IMS 注册完整实现文档（2026-03-26）

本文档给出“从零部署到完成 IMS REGISTER”的完整实现清单，基于当前主机的已验证配置。内容包含模块划分、依赖安装步骤与配置导入步骤，保证可复现。

## 1. 目标与范围

目标：在同一台服务器上完成 VoWiFi IMS 注册链路，做到 UE 侧通过 SWu/IKEv2 建隧道，经 ePDG 接入 IMS，完成标准 IMS REGISTER（401/200 OK）。

范围：
- SWu（UE ↔ ePDG，IKEv2/IPsec）
- SWm（ePDG ↔ AAA，Diameter-EAP）
- IMS 核心（P-/I-/S-CSCF）
- IMS HSS（PyHSS）
- IMS APN 数据面（Open5GS/ogstun）

## 2. 模块与职责

1. UE 模拟（SWu-IKEv2）
- 目录：`/root/epdg_work/SWu-IKEv2`
- 组件：`swu_emulator.py`、`ims_sip_register.py`
- 作用：模拟 UE 发起 IKEv2 + EAP-AKA，完成 IMS REGISTER/INVITE

2. ePDG 控制面（epdg-go）
- 配置：`/etc/epdg-go/epdgd.yaml`
- 作用：协调 SWu/SWm/S2b，调用 strongSwan 建立 Child SA

3. IKEv2/IPsec（strongSwan + swanctl）
- 配置：`/etc/swanctl/conf.d/epdg-ike.conf`
- 作用：真正处理 IKEv2/IPsec，分配 UE 地址池

4. AAA（freeDiameter + swm-aaad）
- 服务：`aaa-freediameter.service`、`swm-aaad.service`
- 作用：承接 SWm（Diameter-EAP）并联动 HSS

5. IMS 核心（Kamailio）
- P-CSCF：`/etc/kamailio_pcscf/*`
- I-CSCF：`/etc/kamailio_icscf/*`
- S-CSCF：`/etc/kamailio_scscf/*`
- 作用：完成 IMS 注册、路由与业务处理

6. IMS HSS（PyHSS）
- 配置：`/etc/pyhss/config.yaml`
- 作用：提供 Cx/Dx/Diameter 鉴权与用户资料

7. IMS APN 数据面（Open5GS）
- 配置：`/etc/open5gs/*`
- 作用：提供 ogstun、IMS APN 地址池与 P-CSCF 可达性

## 3. 依赖安装步骤（Ubuntu 22.04）

以下安装命令假设是“同机部署”的最小依赖集合。若你已安装，可跳过。

1. 系统基础
```bash
sudo apt update
sudo apt install -y git curl jq iproute2 iptables net-tools
```

2. strongSwan 与 swanctl
```bash
sudo apt install -y strongswan strongswan-swanctl libcharon-extra-plugins
```

3. AAA（freeDiameter 及常用工具）
```bash
sudo apt install -y freediameter-utils
```

4. Kamailio（IMS 配置使用）
```bash
sudo apt install -y kamailio kamailio-extra-modules kamailio-mysql-modules
```

5. 数据库与缓存
```bash
sudo apt install -y mariadb-server redis-server
```

6. PyHSS 运行时依赖
```bash
sudo apt install -y python3 python3-venv python3-pip
```

7. SWu-IKEv2 依赖
```bash
sudo apt install -y python3-venv swig libpcsclite-dev pcscd pcsc-tools
```

8. Open5GS（用于 IMS APN/ogstun）
```bash
sudo apt install -y open5gs
```

## 4. 配置导入步骤（推荐顺序）

本机已完成一次配置备份，可直接恢复。备份文件路径：
- `/root/epdg_work/backups/config_backup_20260326_053007.tar.gz`

### 4.1 一键恢复配置

```bash
sudo tar -xzf /root/epdg_work/backups/config_backup_20260326_053007.tar.gz -C /
```

恢复完成后，以下目录会被覆盖：
- `/etc/epdg-go`
- `/etc/swanctl`
- `/etc/strongswan.conf`、`/etc/strongswan.d`
- `/etc/kamailio_pcscf`、`/etc/kamailio_icscf`、`/etc/kamailio_scscf`
- `/etc/pyhss`
- `/etc/open5gs`
- `/root/epdg_work/SWu-IKEv2/*.py`
- `/root/epdg_work/docs`

### 4.2 手工导入（按模块）

如果你只想导入部分模块，按以下路径复制即可：

1. ePDG
```bash
sudo cp -a /root/epdg_work/epdg-go/config/epdgd.yaml /etc/epdg-go/epdgd.yaml
```

2. strongSwan + swanctl
```bash
sudo cp -a /root/epdg_work/epdg-go/config/epdg-ike.conf /etc/swanctl/conf.d/epdg-ike.conf
sudo swanctl --load-all
```

3. Kamailio（P-/I-/S-CSCF）
```bash
sudo cp -a /root/epdg_work/kamailio/pcscf/* /etc/kamailio_pcscf/
sudo cp -a /root/epdg_work/kamailio/icscf/* /etc/kamailio_icscf/
sudo cp -a /root/epdg_work/kamailio/scscf/* /etc/kamailio_scscf/
```

4. PyHSS
```bash
sudo cp -a /root/epdg_work/pyhss/config.yaml /etc/pyhss/config.yaml
```

5. SWu-IKEv2 脚本
```bash
sudo cp -a /root/epdg_work/SWu-IKEv2/ims_sip_register.py /root/epdg_work/SWu-IKEv2/ims_sip_register.py
sudo cp -a /root/epdg_work/SWu-IKEv2/swu_emulator.py /root/epdg_work/SWu-IKEv2/swu_emulator.py
```

## 5. 关键配置项（以当前主机为准）

### 5.1 ePDG（`/etc/epdg-go/epdgd.yaml`）

- SWu 本机地址：`192.168.216.133`
- IKEv2 端口：`500/4500`
- PLMN：`MCC=001`、`MNC=01`
- SWm 对端：`127.0.0.1:13868`
- S2b PGW：`127.0.0.4:2123`

### 5.2 strongSwan（`/etc/swanctl/conf.d/epdg-ike.conf`）

- `local_addrs = 192.168.216.133`
- UE 地址池：`10.46.0.100-10.46.0.200`
- DNS 下发：`8.8.8.8`（可改为 `10.46.0.1`）
- `eap_id = 0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org`

### 5.3 P-/I-/S-CSCF（Kamailio）

- P-CSCF 监听：`10.46.0.2:5060`
- I-CSCF 监听：`10.46.0.2:5061`
- S-CSCF 监听：`10.46.0.2:5062`
- DB URL：`mysql://<user>:<pass>@127.0.0.1/<db>`

参考位置：
- `/etc/kamailio_pcscf/pcscf.cfg`
- `/etc/kamailio_icscf/icscf.cfg`
- `/etc/kamailio_scscf/scscf.cfg`

### 5.4 PyHSS（`/etc/pyhss/config.yaml`）

- `OriginHost = hss.localdomain`
- `OriginRealm = localdomain`
- Cx 监听：`127.0.0.8:3868`
- `MCC=001`、`MNC=01`
- S-CSCF pool：`sip:10.46.0.2:5062`
- 数据库：当前为 `sqlite`（`hss.db`）

### 5.5 IMS APN / ogstun

- 建议 `ogstun` 上配置 `10.46.0.1/32`（DNS）与 `10.46.0.2/32`（P-CSCF）
- 若使用 Open5GS，确保 IMS APN 分配 `10.46.0.0/16`

## 6. 启动顺序与验证

### 6.1 启动顺序

```bash
sudo systemctl restart aaa-freediameter swm-aaad
sudo systemctl restart epdgd
sudo systemctl restart kamailio_pcscf kamailio_icscf kamailio_scscf
sudo systemctl restart pyhss_diameter
```

如果你需要 IMS APN：
```bash
sudo systemctl restart open5gs-smfd open5gs-upfd
```

### 6.2 常用检查

```bash
sudo systemctl status epdgd
sudo systemctl status kamailio_pcscf
sudo systemctl status pyhss_diameter
sudo swanctl --list-conns
```

### 6.3 SWu-IKEv2 模拟注册

在 netns 中运行（避免与 strongSwan 端口冲突）：

```bash
sudo ip netns exec swu1 bash -lc '
  cd /root/epdg_work/SWu-IKEv2 && \
  ./.venv/bin/python3 -u swu_emulator.py \
    -s 172.18.0.2 \
    -d 192.168.216.133 \
    -a ims \
    -M 001 -N 001 \
    -I 001010000000001 \
    -K 465B5CE8B199B49FAA5F0A2EE238A6BC \
    -C E8ED289DEBA9526743BA151B062835CC
'
```

注册/呼叫脚本：

```bash
sudo ip netns exec swu1 bash -lc '
  cd /root/epdg_work/SWu-IKEv2 && \
  ./.venv/bin/python3 -u ims_sip_register.py \
    --local-ip 10.46.0.100 \
    --pcscf-ip 10.46.0.2 \
    --imsi 001010000000001 \
    --register-domain ims.mnc001.mcc001.3gppnetwork.org \
    --public-id sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org \
    --private-id 001010000000001@localdomain \
    --actions register,invite \
    --ki 465B5CE8B199B49FAA5F0A2EE238A6BC \
    --opc E8ED289DEBA9526743BA151B062835CC \
    --invite-port 6063 \
    --contact-port 6062 \
    --sec-port-c 6062 \
    --sec-port-s 6063 \
    --invite-target sip:13800000001@ims.mnc001.mcc001.3gppnetwork.org
'
```

## 7. 注册成功的判定标准

- `REGISTER #1` 返回 `401 Unauthorized`
- `REGISTER #2` 返回 `200 OK`
- `200 OK` 中包含 `P-Associated-URI`、`Service-Route`、`Supported: sec-agree`
- Kamailio P-CSCF 日志记录 `registered` 或 `pcscf_is_registered` 成功

## 8. 常见问题（与当前环境强相关）

1. 本机端口冲突
- UE 模拟器会占用 `UDP/500/4500`，需在 netns 中运行

2. IMS 业务仍被拒绝
- `INVITE` 返回 `403` 时优先检查 P-CSCF 注册态是否落库

3. ogstun/IMS APN 不可达
- 确认 `ogstun` 已添加 `10.46.0.1/32` 与 `10.46.0.2/32`

---

如果你希望我下一步继续完善 INVITE 的注册态同步与排障流程，可以直接说“继续定位 INVITE”。
