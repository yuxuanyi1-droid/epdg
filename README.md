# ePDG Go 独立模块（epdgd）

这个模块用于把 ePDG 控制逻辑独立出来，不和 Open5GS/Kamailio 代码耦合。  
当前版本是可运行骨架，包含：

- 独立配置加载（`configs/epdg.yaml`）
- 会话管理 API（创建、删除、查询）
- AAA 适配层接口（`swm_diameter_eap` / `swm_tcp_probe` / `noop`）
- IPsec 适配层接口（`swanctl` / `noop`）
- S2b 适配层接口（`gtpv2_echo` / `noop`）
- 3GPP 接口配置模型（SWu/SWm/S2b）
- 协议合规自检 API（Open5GS/Kamailio/PyHSS 依赖检查）

## 目录结构

```text
cmd/epdgd/main.go            # 入口
internal/config              # 配置
internal/app                 # HTTP API
internal/session             # 会话状态存储
internal/aaa                 # AAA 接口
internal/ipsec               # IPsec 接口（strongSwan 适配）
configs/epdg.yaml            # 示例配置
```

## 运行

```bash
cd /root/epdg_work/epdg-go
go mod tidy
go run ./cmd/epdgd ./configs/epdg.yaml
```

开发模式（不依赖本机 IPsec 组件）：

```bash
go run ./cmd/epdgd ./configs/epdg.dev.yaml
```

标准推进模式（SWm Diameter-EAP 骨架）：

```bash
go run ./cmd/epdgd ./configs/epdg.std.yaml
```

独立 AAA（freeDiameter）模式：

- `SWm` 对接地址可设为独立 AAA：`127.0.0.1:13868`
- 当前环境服务：`aaa-freediameter.service`
- AAA 配置：`/etc/freeDiameter/aaa_swm.conf`
- SWm 业务应答服务：`swm-aaad.service`
- Handler 配置：`/etc/epdg-go/swm-aaad.yaml`

## strongSwan EAP-AKA 说明

- 当前环境已加载 `eap-aka` / `eap-dynamic` / `eap-radius` 插件（`swanctl --stats` 可见）。
- 示例 IKEv2 配置模板：`deploy/strongswan/epdg_ikev2_eap_aka.swanctl.conf.example`
- 注意：`eap-aka` 仅解决 SWu 侧 EAP 方法；**标准 ePDG 仍需 SWm 到 AAA（Diameter-EAP）**，本项目通过独立 AAA 节点实现该路径。

## API

- `GET /healthz`：健康检查
- `GET /v1/sessions`：会话列表
- `POST /v1/sessions/create`：创建会话
- `POST /v1/sessions/delete`：删除会话
- `GET /v1/compliance/check`：标准协议落地自检

### 创建会话示例

```bash
curl -sS -X POST http://127.0.0.1:19090/v1/sessions/create \
  -H 'Content-Type: application/json' \
  -d '{"ue_id":"ue-001","imsi":"001010000000001","apn":"ims"}'
```

## 与现网解耦设计说明

- 本模块不修改 Open5GS/Kamailio 进程配置。
- 通过适配层对接外部组件：
  - AAA: 已支持 SWm Diameter-EAP 骨架（CER/CEA + DER/DEA）
  - IPsec: 通过 `swanctl` 执行 Child SA 建立/释放
- 生产建议使用 `configs/epdg.yaml`（`ipsec.backend: swanctl`）。
- 联调建议使用 `configs/epdg.dev.yaml`（`ipsec.backend: noop`）先验证控制面流程。

## swanctl 后端行为

- `ipsec.mode: active` 时，创建会话执行：`swanctl --initiate --child <child> [--ike <connection_name>]`
- `ipsec.mode: passive` 时，不主动发起 IKEv2，而是校验连接已加载并返回“等待 UE 发起”
- 删除会话时执行：`swanctl --terminate --child <child>`
- `child` 名规则：`<child_prefix>-<ue_id>`

示例：`ue_id=ue-001` 且 `child_prefix=ue`，则 Child 名为 `ue-ue-001`。

## strongSwan 预置示例

- 示例文件：`deploy/swanctl/epdg-ike.conf.example`
- 加载示例：

```bash
cp deploy/swanctl/epdg-ike.conf.example /etc/swanctl/conf.d/epdg-ike.conf
systemctl restart strongswan
swanctl --load-all
```

若 `systemctl status strongswan` 出现 `could not create any sockets`，通常是宿主内核/容器能力限制（常见于 WSL），需在具备完整 IPsec/XFRM 能力的 Linux 主机验证真实 IKE/ESP。

## 标准协议说明（当前实现边界）

- SWu：由 strongSwan（IKEv2/IPsec）承载，本模块通过 `swanctl` 控制 Child SA 生命周期。
- SWm：支持 `swm_diameter_eap`（CER/CEA + DER/DEA 骨架）和 `swm_tcp_probe`。
- S2b：当前用 `gtpv2_echo` 做 GTPv2-C Echo 检测（会话创建前校验）。

## 关键配置项

- `aaa.backend`: `swm_diameter_eap` / `swm_tcp_probe` / `noop`
- `aaa.origin_host/origin_realm/destination_host/destination_realm`: SWm Diameter 标识参数
- `aaa.eap_provider`: `unsupported` / `nak_only`
- `aaa.eap_max_rounds`: SWm EAP 最大交互轮次
- `protocol.s2b.backend`: `gtpv2_echo`（推荐）或 `noop`
- `protocol.swm.peer_host/realm/port`: SWm 对端
- `protocol.s2b.pgw_address/gtpv2_port`: S2b 对端

说明：当前方案保持 `PyHSS` 源码不改；`SWm DER/DEA` 由独立 `freeDiameter + swm-aaad` 处理，`PyHSS` 继续负责既有 HSS 接口。
- 已验证：`freeDiameter -> swm-aaad` 多轮 `DER/DEA` 已通。
- 已验证：`swm-aaad -> freeDiameter -> epdgd` 的 `DEA(1001/2001)` 回送已通。
- 已验证：`ipsec.mode: passive` 下，`create session` 会返回 `pending`，明确等待 UE 发起 `IKEv2/IPsec`
- 当前剩余瓶颈：需要真实 UE / 模拟 UE 发起 `SWu`，才能从 `pending` 进入真正的 `IPsec/S2b` 后续流程
- 自检说明：`/v1/compliance/check` 对 `swm_diameter_eap` 现使用端口可达性检查，避免干扰持久 Diameter peer。

当前默认不修改 `PyHSS` 源码；如需完整 SWm EAP-AKA'，建议通过独立 AAA 组件实现并在配置层对接。
