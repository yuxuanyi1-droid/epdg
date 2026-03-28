# Kamailio 部署（IMS）

## 1. 依赖安装（Ubuntu/Debian）

```bash
sudo apt update
sudo apt install -y kamailio kamailio-mysql-modules kamailio-extra-modules
```

IMS 模块通常需要 `ims_*` 相关包，若系统拆包提供：

```bash
sudo apt install -y kamailio-ims-modules
```

## 2. 配置目录与覆盖

系统目录：

- `/etc/kamailio_pcscf`
- `/etc/kamailio_icscf`
- `/etc/kamailio_scscf`

仓库配置（已与当前系统配置一致）：

- `configs/kamailio/pcscf/*`
- `configs/kamailio/icscf/*`
- `configs/kamailio/scscf/*`

当前已跑通关键点：

- P-CSCF 已启用 `#!define WITH_IPSEC`
- P-CSCF 已启用 `#!define STRICT_IMS_IPSEC`
- `REGISTER 200 OK` 在严格模式下通过 `ipsec_forward("location")` 回包

覆盖命令：

```bash
sudo rsync -av --delete configs/kamailio/pcscf/ /etc/kamailio_pcscf/
sudo rsync -av --delete configs/kamailio/icscf/ /etc/kamailio_icscf/
sudo rsync -av --delete configs/kamailio/scscf/ /etc/kamailio_scscf/
```

## 3. 启动服务

```bash
sudo systemctl enable --now kamailio_pcscf
sudo systemctl enable --now kamailio_icscf
sudo systemctl enable --now kamailio_scscf
```

## 4. 快速检查

```bash
systemctl is-active kamailio_pcscf kamailio_icscf kamailio_scscf
journalctl -u kamailio_pcscf -n 50 --no-pager
journalctl -u kamailio_icscf -n 50 --no-pager
journalctl -u kamailio_scscf -n 50 --no-pager
```

## 5. 说明

当前已验证重点在 SWu 接入链路（EAP-AKA + IKEv2/IPsec）和 IMS REGISTER（`401 -> 200 OK`）。

## 6. 数据库备份（迁移推荐）

Kamailio IMS 三库建议一起迁移：

```bash
mysqldump -u root -p --databases pcscf icscf scscf > kamailio_ims.sql
```

恢复：

```bash
mysql -u root -p < kamailio_ims.sql
```
