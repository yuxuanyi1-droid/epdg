# ePDG 控制面

这个仓库现在的主线是：

- `pyepdg/`：Python 版 ePDG 控制面与会话编排
- `pyhss/`：官方 PyHSS 代码树，承担 HSS 和 AAA 能力

外部组件仍然保持独立：

- `strongSwan`：承载 SWu / IKEv2 / IPsec
- `Kamailio`：承载 IMS 的 P-CSCF / I-CSCF / S-CSCF
- `Open5GS`：承载 EPC 必要网元

## 目录

```text
pyepdg/                   # Python ePDG 控制面
pyhss/                    # PyHSS 源码
configs/epdg/             # ePDG 配置示例
configs/kamailio/         # IMS 配置
configs/open5gs/          # EPC 配置
configs/strongswan/       # strongSwan/ePDG 配置
configs/pyhss/            # PyHSS 运行配置备份
database/                 # 数据库备份与恢复脚本
docs/                     # 分模块部署文档
test/                     # SWu + VoWiFi 注册联调脚本
```

## 运行

标准配置直接对接 PyHSS：

```bash
python3 -m pyepdg ./configs/epdg/epdg.yaml
```

开发配置只保留本地编排：

```bash
python3 -m pyepdg ./configs/epdg/epdg.dev.yaml
```

## AAA

ePDG 的 AAA 直接由 PyHSS 提供。

现在默认通过 PyHSS 的 SWm 风格 API 获取 EAP-AKA 相关数据：

- `GET /auc/swm/eap_aka/plmn/<plmn>/imsi/<imsi>`
- `GET /oam/ping`

对应逻辑在 [pyhss/services/apiService.py](/home/yuxuanyi/epdg/pyhss/services/apiService.py) 和 [pyepdg/pyhss_client.py](/home/yuxuanyi/epdg/pyepdg/pyhss_client.py)。

## API

- `GET /healthz`
- `GET /v1/sessions`
- `POST /v1/sessions/create`
- `POST /v1/sessions/delete`
- `GET /v1/compliance/check`

## 当前已验证结果

- SWu IKEv2 + EAP-AKA：可建立 IKE_SA / CHILD_SA
- IMS REGISTER：`401` 挑战后 `200 OK` 成功
- P-CSCF：已启用严格 IMS IPsec 回包模式（`STRICT_IMS_IPSEC`）

一键回归命令（当前仓库）：

```bash
./test/run.sh
```

## 说明

- `configs/epdg/epdg.yaml` 和 `configs/epdg/epdg.std.yaml` 默认指向 PyHSS。
- `configs/epdg/epdg.dev.yaml` 适合本地调试，不发起真实 IPsec / S2b 动作。
- 如果后续你想把 PyHSS 再进一步收敛成真正的 Diameter SWm 服务，我们可以在 `pyhss/` 里继续补那层实现。
