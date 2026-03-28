# Open5GS 部署（EPC 必要模块）

## 1. 依赖安装（Ubuntu/Debian）

```bash
sudo apt update
sudo apt install -y software-properties-common gnupg curl
sudo add-apt-repository -y ppa:open5gs/latest
sudo apt update
sudo apt install -y open5gs mongodb
```

## 2. 使用仓库配置

仓库内已对齐可用配置（与 `/etc/open5gs` 当前配置一致）：

- `configs/open5gs/mme.yaml`
- `configs/open5gs/sgwc.yaml`
- `configs/open5gs/sgwu.yaml`
- `configs/open5gs/hss.yaml`
- `configs/open5gs/pcrf.yaml`

覆盖到系统目录：

```bash
sudo cp configs/open5gs/mme.yaml /etc/open5gs/mme.yaml
sudo cp configs/open5gs/sgwc.yaml /etc/open5gs/sgwc.yaml
sudo cp configs/open5gs/sgwu.yaml /etc/open5gs/sgwu.yaml
sudo cp configs/open5gs/hss.yaml /etc/open5gs/hss.yaml
sudo cp configs/open5gs/pcrf.yaml /etc/open5gs/pcrf.yaml
```

## 3. 启动 EPC 必要模块

```bash
sudo systemctl enable --now mongodb
sudo systemctl enable --now open5gs-mmed open5gs-sgwcd open5gs-sgwud
```

可选（仅当需要 Open5GS 内置 HSS/PCRF 时）：

```bash
sudo systemctl enable --now open5gs-hssd open5gs-pcrfd
```

## 4. 快速检查

```bash
systemctl is-active open5gs-mmed open5gs-sgwcd open5gs-sgwud
journalctl -u open5gs-mmed -n 50 --no-pager
```

## 5. 说明

当前实验链路核心依赖是 `MME/SGWC/SGWU`，AAA 由 PyHSS 提供，不强依赖 Open5GS HSS。
