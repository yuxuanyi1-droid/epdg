# SWu-IKEv2 非 Docker 模拟 UE 测试记录

## 当前结论

当前机器已经可以使用源码方式运行 `SWu-IKEv2` 客户端，但在这台 `WSL2` 主机上，**标准 IKEv2 端口 `UDP/500` 与 `UDP/4500` 无法被 strongSwan 正常监听并接收报文**，因此暂时不能在本机完成标准 `SWu` 端到端建隧道验证。

这不是 `SWu-IKEv2` 客户端本身的问题，现网已经验证到：

- `SWu-IKEv2` 源码已拉取并完成依赖安装
- Python 虚拟环境已就绪：`/root/epdg_work/SWu-IKEv2/.venv`
- 同机测试时，客户端直接绑定本地 `500/4500` 会与服务端冲突
- 将客户端移入独立 `netns` 后，客户端可正常发出 `IKE_SA_INIT`
- 但服务端 `strongSwan` 没有收到任何 `IKE_SA_INIT`，客户端持续超时

## 已完成的现网准备

### 1. 客户端源码与依赖

源码目录：

- `/root/epdg_work/SWu-IKEv2`

已安装依赖包括：

- `python3-pyscard`
- `libpcsclite-dev`
- `pcscd`
- `pcsc-tools`
- `python3-venv`
- `swig`

并已完成：

- `.venv` 创建
- `pip install -r requirements.txt`
- 给虚拟环境 Python 增加 `cap_net_bind_service,cap_net_raw`

### 2. 现网参数

当前测试按以下实验参数执行：

- ePDG 地址：`10.46.0.2`
- APN：`ims`
- IMSI：`001010000000001`
- MCC：`001`
- MNC：`001`

说明：

- `PyHSS/Open5GS` 当前配置为 `MCC=001`、`MNC=01`
- `SWu-IKEv2` 客户端要求 `MNC` 按 3 位传入，因此这里使用 `001`
- `KI/OPC` 取自实验脚本 `/root/epdg_work/pyhss/add_subscriber.py`

### 3. 独立 netns 方式

因为客户端本身也要占用本地 `UDP/500`、`UDP/4500`，同机直跑必然和服务端冲突，所以增加了以下辅助脚本：

- `epdg-go/scripts/setup_swu_netns.sh`
- `epdg-go/scripts/run_swu_ikev2.sh`
- `epdg-go/scripts/cleanup_swu_netns.sh`

推荐使用方式：

```bash
/root/epdg_work/epdg-go/scripts/setup_swu_netns.sh
/root/epdg_work/epdg-go/scripts/run_swu_ikev2.sh
/root/epdg_work/epdg-go/scripts/cleanup_swu_netns.sh
```

## 本机实测现象

### 1. 同机同命名空间直跑

直接执行 `SWu-IKEv2` 时，客户端报错：

- `OSError: [Errno 98] Address already in use`

这是因为它会绑定本地：

- `UDP/500`
- `UDP/4500`

### 2. 独立 netns 试跑

在 `swu1` 网络命名空间中执行后，客户端进入标准流程并发送 `IKE_SA_INIT`：

- `STATE 1`
- `sending IKE_SA_INIT`

但随后连续出现：

- `TIMEOUT : TIMEOUT`

### 3. 服务端现象

在同一时间窗口内：

- `strongSwan` 日志没有出现新的 `IKE_SA_INIT` 收包记录
- `ss`/`lsof` 看不到 `UDP/500`、`UDP/4500` 正常监听
- 但 Python 手动绑定这些端口时仍返回 `Address already in use`

这说明在当前 `WSL2` 环境中，`500/4500` 被系统层占用或拦截，导致：

- `strongSwan` 无法建立标准 IKEv2 接收 socket
- `SWu-IKEv2` 发出的报文无法被本机 ePDG 进程接收

## 对标准协议实现的影响

这不会影响我们当前已经完成的以下部分：

- `SWm`：`freeDiameter + swm-aaad` 已通
- `DER/DEA`：已通
- `S2b`：GTPv2 Echo 探测已通
- `Kamailio/Open5GS/P-CSCF`：现网配置保留

当前唯一没有在本机完成“实收包验证”的部分是：

- `SWu IKEv2/IPsec`

## 下一步建议

如果目标是**严格按标准协议完成端到端收包与建隧道验证**，建议把当前整套环境迁移到以下任一环境：

- 原生 Ubuntu 22.04 物理机
- KVM/VMware/VirtualBox 虚拟机
- 裸金属云主机

迁移后，优先复用当前目录中的现有成果：

- `SWu-IKEv2` 客户端源码与虚拟环境方案
- `freeDiameter + swm-aaad`
- `strongSwan + swanctl`
- `epdg-go`

这样可以最快恢复到“只差 `SWu` 收包验证”的状态。
