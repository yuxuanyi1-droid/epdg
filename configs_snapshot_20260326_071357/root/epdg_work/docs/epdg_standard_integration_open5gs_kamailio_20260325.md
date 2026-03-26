# ePDG 标准协议集成说明（Open5GS + Kamailio，2026-03-25）

## 1) 标准接口目标

- SWu：UE ↔ ePDG（IKEv2/IPsec，UDP 500/4500）
- SWm：ePDG ↔ 3GPP AAA（Diameter-EAP，典型 EAP-AKA'）
- S2b：ePDG ↔ PGW（GTPv2-C/GTP-U）

## 2) 当前实现状态（本仓库）

- 已实现：
  - Go 独立 ePDG 控制模块（`epdg-go`）
  - `swanctl` Child SA 建立/释放调用
  - 标准接口配置模型（SWu/SWm/S2b）
  - `/v1/compliance/check` 合规自检接口
  - SWm `swm_tcp_probe` 门禁（会话创建前检查 Diameter 对端可达）
  - SWm `swm_diameter_eap`（CER/CEA + DER/DEA 多轮状态机骨架）
  - SWm 通过独立 AAA 节点（freeDiameter）前置对接，PyHSS 保持源码不改
  - S2b `gtpv2_echo` 门禁（会话创建前检查 GTPv2 Echo）
- 未实现（需后续补齐）：
  - SWm Diameter-EAP 全流程（EAP-AKA'，当前仅多轮框架与占位响应器）
  - S2b 真实控制面会话流程（Create Session / Bearer）

## 3) 与现网组件关系

- Open5GS / Kamailio / PyHSS 继续独立运行，不直接改动其核心代码。
- ePDG 模块通过“配置+接口”方式集成，不与 IMS/EPC 代码耦合。
- 新增独立 AAA：`freeDiameter`（`aaa-freediameter.service`），作为 SWm 前置节点。
- 新增独立 SWm 处理器：`swm-aaad`（`swm-aaad.service`）。
- 当前 SWm 路径：`epdgd -> freeDiameter(127.0.0.1:13868) -> swm-aaad(127.0.0.19:3869)`。
- 当前联调结论：
  - `DER/DEA` 多轮流程已打通；
  - `DEA(1001/2001)` 已可经 `freeDiameter` 正常回送给 `epdgd`；
  - ePDG 已改为更标准的被动 `SWu` 行为：`ipsec.mode: passive`
  - 当前 `create session` 返回 `pending`，消息为等待 UE 发起 `IKEv2/IPsec on child ue-default`

## 4) 合规自检接口

```bash
curl -sS http://127.0.0.1:19091/v1/compliance/check | jq
```

检查项包含：
- SWu 基本参数完整性
- SWm 对端可达性（TCP/3868）
- S2b PGW GTPv2 可达性（GTPv2 Echo）
- Open5GS EPC 服务状态
- Kamailio IMS SIP 监听状态
- PyHSS 服务状态

## 5) 下一阶段建议（标准协议闭环）

1. 启用可用 Linux 内核环境（支持 IPsec/XFRM，非受限 WSL）
2. strongSwan 侧启用 IKEv2 EAP-AKA 方法（插件已就绪）
3. 将独立 `swm-aaad` 演进为完整 SWm EAP-AKA' 鉴权服务
4. 对接真实 SWu/IKEv2 发起端（真实 UE 或支持 IKEv2/EAP-AKA' 的模拟器）
5. 在 UE 发起成功后补 `pending -> up` 的状态联动
6. 对接 S2b 控制面流程（与 PGW/UPF 对接）
7. 用支持 IKEv2+EAP-AKA' 的 UE/模拟器做端到端验收
