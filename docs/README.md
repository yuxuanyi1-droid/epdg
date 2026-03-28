# 部署文档总览

本目录按模块拆分部署说明：

- `open5gs.md`：EPC 侧（MME/SGWC/SGWU/PCRF/HSS）安装与启动。
- `kamailio.md`：IMS 侧（P-CSCF/I-CSCF/S-CSCF）安装与启动。
- `strongswan.md`：ePDG IKEv2/IPsec 与 EAP-RADIUS 对接配置。
- `pyhss.md`：PyHSS 安装、配置、API 启动与 AAA Bridge 启动。
- `pyepdg.md`：Python 编排层（pyepdg）安装与启动。

建议启动顺序：

1. Open5GS
2. PyHSS
3. strongSwan
4. Kamailio
5. pyepdg

验证命令参考各文档末尾“快速检查”章节。

端到端 VoWiFi 注册回归：

```bash
cd /home/yuxuanyi/epdg
./test/run.sh
```

预期结果：输出中可见第二次 REGISTER 收到 `SIP/2.0 200 OK`。

## 迁移建议（数据库）

跨环境快速恢复时，建议同时迁移配置和数据库：

- Kamailio MySQL：`pcscf` / `icscf` / `scscf`
- PyHSS 数据库：当前环境默认是 SQLite（`/var/lib/pyhss/hss.db`）
- Open5GS MongoDB：`open5gs`

参考命令：

```bash
# 1) 导出 Kamailio MySQL
mysqldump -u root -p --databases pcscf icscf scscf > kamailio_ims.sql

# 2) 备份 PyHSS SQLite
cp /var/lib/pyhss/hss.db pyhss_hss.db

# 3) 导出 Open5GS MongoDB
mongodump --db open5gs --out ./mongo_backup

# 4) 在新环境恢复（示例）
mysql -u root -p < kamailio_ims.sql
cp pyhss_hss.db /var/lib/pyhss/hss.db
chown pyhss:pyhss /var/lib/pyhss/hss.db
mongorestore --drop --db open5gs ./mongo_backup/open5gs
```

若当前环境没有 `mongodump`，可使用仓库脚本（Mongo 服务可达时）：

```bash
cd /home/yuxuanyi/epdg
./database/scripts/backup_open5gs_json.py
```

一键恢复（Kamailio + PyHSS）：

```bash
cd /home/yuxuanyi/epdg
./database/scripts/restore_all.sh
```
