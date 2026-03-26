# 原生 Ubuntu / VM 迁移说明

## 目标

把当前 `WSL2` 上已经完成的以下能力迁移到可直接跑标准 `SWu IKEv2/IPsec` 的 Linux 环境：

- Open5GS EPC
- Kamailio IMS
- PyHSS
- strongSwan / swanctl
- freeDiameter + `swm-aaad`
- `epdg-go`
- `SWu-IKEv2` 非 Docker 测试客户端

## 为什么要迁移

当前 `WSL2` 主机上，标准 IKE 端口：

- `UDP/500`
- `UDP/4500`

存在实际收包异常，导致：

- `SWu-IKEv2` 能发出 `IKE_SA_INIT`
- 但本机 `strongSwan` 无法正常接收并推进标准 `SWu` 建隧道

因此如果目标是**严格按标准协议完成端到端验证**，需要迁移到：

- 原生 Ubuntu 22.04
- 或完整 Linux 虚拟机

## 已准备的迁移材料

### 导出脚本

- `epdg-go/scripts/export_native_migration_bundle.sh`

执行后会导出：

- 工作区源码
- 关键 `/etc` 配置
- systemd 单元
- 文档

### 非 Docker SWu 测试脚本

- `epdg-go/scripts/setup_swu_netns.sh`
- `epdg-go/scripts/run_swu_ikev2.sh`
- `epdg-go/scripts/cleanup_swu_netns.sh`

## 建议恢复顺序

1. 安装基础依赖
2. 恢复 `/root/epdg_work`
3. 恢复 `/etc/open5gs`
4. 恢复 `/etc/kamailio_*`
5. 恢复 `/etc/swanctl`
6. 恢复 `/etc/freeDiameter`
7. 恢复 `/etc/epdg-go`
8. 恢复 systemd 单元
9. `systemctl daemon-reload`
10. 启动并联调：
   - `strongswan`
   - `pyhss_*`
   - `aaa-freediameter`
   - `swm-aaad`
   - Open5GS
   - Kamailio IMS

## 第一轮迁移后优先验证

建议按这个顺序验证：

1. `strongSwan` 是否真正监听 `UDP/500` 和 `UDP/4500`
2. `SWu-IKEv2` 是否收到 `IKE_SA_INIT` 响应
3. `SWm` 的 `DER/DEA` 是否继续正常
4. `S2b` Echo 是否继续正常
5. `Kamailio IMS` 注册链路是否保持

## 迁移后的成功标志

至少出现以下现象才算真正完成下一阶段：

- `SWu-IKEv2` 不再 `TIMEOUT`
- `strongSwan` 日志出现 `IKE_SA_INIT` / `IKE_AUTH`
- UE 获取到分配地址
- `epdg-go` 可把会话从 `pending` 推进到 `up`
