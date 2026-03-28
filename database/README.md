# 数据备份目录

本目录用于保存“可快速迁移到新环境”的数据库快照和恢复脚本。

## 当前已备份

- `kamailio/kamailio_ims.sql`
  - 来源：`mysqldump --databases pcscf icscf scscf`
- `pyhss/hss.db`
  - 来源：`/var/lib/pyhss/hss.db`
- `open5gs/open5gs_json/`
  - 预留目录；需要在 MongoDB 服务可达后执行导出脚本生成 JSON 快照

## 恢复脚本

- `scripts/restore_all.sh`
  - 恢复 Kamailio MySQL + PyHSS SQLite
- `scripts/backup_open5gs_json.py`
  - 当 `mongodb://127.0.0.1:27017` 可达时，导出 `open5gs` DB 为 JSON 行文件

## 说明

如果目标环境没有安装 `mongodump`，可用 `backup_open5gs_json.py` 做可读备份。
生产级备份仍建议优先使用 `mongodump/mongorestore`。
