# PyHSS 部署（HSS + SWm AAA）

## 1. 系统依赖

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip redis-server
```

## 2. Python 依赖安装

在仓库根目录执行：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r pyhss/requirements.txt
pip install -r requirements.txt
```

## 3. PyHSS 基础服务

按需启动 API（实验环境最少要求）：

```bash
source .venv/bin/activate
export PYHSS_CONFIG=/etc/pyhss/config.yaml
python3 pyhss/services/apiService.py
```

当前运行配置已同步到仓库：

- `configs/pyhss/config.yaml`

若需全量服务，可参考 PyHSS systemd 文件（`pyhss/systemd/`）部署。

## 4. 启动 AAA Bridge（EAP-AKA <-> RADIUS）

当前可用实现：

- `pyhss/services/radiusBridgeService.py`

启动命令：

```bash
source .venv/bin/activate
export PYHSS_RADIUS_SECRET=pyhss-radius-secret
export PYHSS_RADIUS_BIND=127.0.0.1
export PYHSS_RADIUS_PORT=18120
export PYHSS_API_BASE=http://127.0.0.1:8080
export PYHSS_PLMN=001001
python3 pyhss/services/radiusBridgeService.py
```

## 5. 快速检查

```bash
curl -s http://127.0.0.1:8080/oam/ping
ss -lunp | grep 18120
```

## 6. 说明

当前链路已验证：

- Access-Challenge / Access-Accept 的 EAP-AKA 状态机可跑通。
- strongSwan 可基于返回的 MSK 建立 IKE/CHILD SA。

## 7. 数据库备份（迁移推荐）

当前环境 `/etc/pyhss/config.yaml` 使用 SQLite：

- `database.db_type: sqlite`
- `database.database: /var/lib/pyhss/hss.db`

迁移时请备份并恢复该文件：

```bash
cp /var/lib/pyhss/hss.db pyhss_hss.db
cp pyhss_hss.db /var/lib/pyhss/hss.db
chown pyhss:pyhss /var/lib/pyhss/hss.db
```
