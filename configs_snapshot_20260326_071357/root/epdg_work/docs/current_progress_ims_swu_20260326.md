# 当前进展与配置说明（2026-03-26）

## 1. 当前总体状态

当前远端服务器 `192.168.9.102` 上已完成以下链路：

- `SWu / IKEv2 / EAP-AKA / IPsec CHILD_SA` 已可建立
- `ePDG` 已健康运行
- `Kamailio P-CSCF / I-CSCF / S-CSCF` 已可启动并联动
- `PyHSS` 已恢复为仅配置方案，未修改源码
- `freeDiameter + swm-aaad` 已作为独立 AAA 链路接入
- `IMS REGISTER` 已可走到标准 IMS 域并返回 `200 OK`

当前仍未完全跑通的是：

- `INVITE` 业务请求仍会返回 `403 Forbidden - You must register first with a S-CSCF`

这说明：

- 接入层已经通
- 注册层已经通
- 业务层后续请求还需要继续对齐 `P-CSCF / S-CSCF` 的注册态与路由态

---

## 2. 当前已确认的有效配置

### 2.1 现网地址

- `ePDG / P-CSCF / I-CSCF / S-CSCF` 统一使用：`10.46.0.2`
- UE 内层地址：`10.46.0.100`
- 远端测试机：`192.168.9.102`

### 2.2 SWu / UE 模拟

UE 模拟器位于：

- `/root/epdg_work/SWu-IKEv2/swu_emulator.py`
- `/root/epdg_work/SWu-IKEv2/ims_sip_register.py`

当前支持：

- `--ims-register`
- `register`
- `re-register`
- `de-register`
- `invite`

当前建议用法：

```bash
cd /root/epdg_work/SWu-IKEv2
ip netns exec swu1 ./.venv/bin/python3 -u ims_sip_register.py \
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
```

### 2.3 IMS 注册脚本当前行为

`ims_sip_register.py` 已做了以下处理：

- 归一化 `sip:` / `sips:` / `tel:` URI，避免重复拼接前缀
- `REGISTER` 使用标准 IMS 域：`ims.mnc001.mcc001.3gppnetwork.org`
- `From` / `To` 已按标准 IMS 形式发送
- `Security-Client` / `Security-Verify` 已接入
- `REGISTER #2` 已可稳定返回 `200 OK`
- `INVITE` 已可发出，但当前仍被核心网拒绝

### 2.4 Kamailio / IMS

当前远端已恢复的服务：

- `kamailio_pcscf`
- `kamailio_icscf`
- `kamailio_scscf`
- `PyHSS`
- `freeDiameter`
- `swm-aaad`
- `epdgd`

---

## 3. 当前可复现的测试结果

### 3.1 注册成功

当前标准 IMS 域注册流程可以跑通：

- `REGISTER #1 -> 100 Trying`
- `REGISTER #1 -> 401 Unauthorized`
- `REGISTER #2 -> 100 Trying`
- `REGISTER #2 -> 200 OK`

典型成功返回里会看到：

- `P-Associated-URI`
- `Service-Route: <sip:orig@10.46.0.2:5062;lr>`
- `Supported: sec-agree`
- `Require: sec-agree`

### 3.2 INVITE 当前状态

`INVITE` 目前会到 `P-CSCF`，但返回：

- `403 Forbidden - You must register first with a S-CSCF`

这说明：

- SIP 报文已进入核心网
- 但后续业务请求仍未被核心网识别为已完成注册的 UE
- 需要继续对齐 `Contact` / `Path` / `Service-Route` / `Security-Verify` / 注册态绑定

---

## 4. 关键配置位置

### 4.1 本地工作区

- `/root/epdg_work/SWu-IKEv2/ims_sip_register.py`
- `/root/epdg_work/SWu-IKEv2/swu_emulator.py`

### 4.2 远端服务器

- `/root/epdg_work/SWu-IKEv2/ims_sip_register.py`
- `/root/epdg_work/SWu-IKEv2/swu_emulator.py`
- `/root/epdg_work/docs/current_progress_ims_swu_20260326.md`

### 4.3 远端 IMS/Kamailio 配置

常见路径：

- `/etc/kamailio_pcscf/`
- `/etc/kamailio_icscf/`
- `/etc/kamailio_scscf/`
- `/etc/freeDiameter/`
- `/etc/epdg-go/`
- `/etc/swanctl/conf.d/`
- `/etc/strongswan.d/charon/`

---

## 5. 注意事项

### 5.1 不要随便改回域名解析链

当前环境已经尽量做成“全 IP 化”以减少解析问题：

- `10.46.0.2` 作为 IMS 核心网地址
- `ims.mnc001.mcc001.3gppnetwork.org` 仅作为 IMS 注册域

建议不要再把核心链路改回依赖本地域名解析，除非你明确知道要测试哪一层。

### 5.2 `REGISTER` 和 `INVITE` 是两层

当前已经证明：

- `REGISTER` 可成功
- `INVITE` 仍需继续排查

不要把这两个结果混为一层。注册成功不代表业务请求自动放行。

### 5.3 `pcscf.location` / `scscf.contact` 可能残留脏状态

如果出现奇怪的 `503`、`504`、`update_contacts()` 错误，优先检查数据库：

```bash
mysql -u root -e 'select count(*) from pcscf.location;'
mysql -u root -e 'select * from scscf.contact\\G'
mysql -u root -e 'select * from scscf.impu_contact\\G'
```

必要时可清理后重启三套 Kamailio：

```bash
mysql -u root -e 'delete from pcscf.location; delete from scscf.contact; delete from scscf.impu_contact;'
systemctl restart kamailio_pcscf kamailio_icscf kamailio_scscf
```

### 5.4 `swu1` netns 运行时

如果要跑 UE 模拟器，请确认：

- `swu1` netns 存在
- `tun1` 已创建并 `UP`
- `10.46.0.100` 已存在于 `tun1`
- 不要让 `10.46.0.2` 的路由绕过 `tun1`

### 5.5 脚本同步

如果你在本地改了 `ims_sip_register.py` 或 `swu_emulator.py`，记得同步到远端：

```bash
sshpass -p root scp -o StrictHostKeyChecking=no \
  /root/epdg_work/SWu-IKEv2/ims_sip_register.py \
  root@192.168.9.102:/root/epdg_work/SWu-IKEv2/ims_sip_register.py
```

---

## 6. 建议的下一步

当前最自然的下一步是继续处理：

- `INVITE` 的 `403`
- `P-CSCF / S-CSCF` 对注册态的绑定
- `Service-Route` / `Path` / `Contact` 的进一步对齐

如果你只想先做验证，建议优先跑：

1. `REGISTER`
2. `REGISTER + INVITE`
3. `re-REGISTER`
4. `de-REGISTER`

