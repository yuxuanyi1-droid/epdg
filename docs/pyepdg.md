# pyepdg 部署（Python 编排层）

## 1. 依赖安装

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## 2. 配置文件

可用配置：

- `configs/epdg/epdg.yaml`：默认标准运行配置
- `configs/epdg/epdg.std.yaml`：标准模板
- `configs/epdg/epdg.dev.yaml`：开发调试

关键字段：

- `ipsec.backend: swanctl`
- `aaa.backend: pyhss_api`
- `aaa.pyhss_api.base_url: http://127.0.0.1:8080`

## 3. 启动

```bash
source .venv/bin/activate
python3 -m pyepdg configs/epdg/epdg.yaml
```

## 4. 健康检查

默认监听 `0.0.0.0:8081`，可通过健康端点检查：

```bash
curl -s http://127.0.0.1:8081/healthz
```

预期会同时检查：

- PyHSS API 可达性
- strongSwan/swanctl 可执行性

## 5. 说明

pyepdg 负责 API 与会话编排，不替代 strongSwan 的 IKE/IPsec 数据面实现。
