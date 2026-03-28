# strongSwan 部署（ePDG IKEv2/IPsec）

## 1. 依赖安装（Ubuntu/Debian）

```bash
sudo apt update
sudo apt install -y strongswan strongswan-pki libcharon-extra-plugins
```

## 2. 使用已验证配置

已跑通配置已固化到仓库：

- `configs/strongswan/swanctl/conf.d/epdg-ike.conf`
- `configs/strongswan/swanctl/conf.d/epdg-aka-secrets.conf`
- `configs/strongswan/strongswan.d/charon/eap-radius.conf`
- `configs/strongswan/swanctl/conf.d/ue-sim.conf.disabled`（测试参考）

覆盖到系统：

```bash
sudo cp configs/strongswan/swanctl/conf.d/epdg-ike.conf /etc/swanctl/conf.d/epdg-ike.conf
sudo cp configs/strongswan/swanctl/conf.d/epdg-aka-secrets.conf /etc/swanctl/conf.d/epdg-aka-secrets.conf
sudo cp configs/strongswan/strongswan.d/charon/eap-radius.conf /etc/strongswan.d/charon/eap-radius.conf
```

## 3. 证书与私钥

当前配置默认使用：

- `/etc/swanctl/x509/epdg.crt`
- `/etc/swanctl/private/epdg.key`

仓库已同步备份（迁移可直接回灌）：

- `configs/strongswan/swanctl/x509/epdg.crt`
- `configs/strongswan/swanctl/private/epdg.key`
- `configs/strongswan/swanctl/x509ca/epdg-ca.crt`

若重建证书，可参考：

```bash
sudo pki --gen --type rsa --size 2048 --outform pem > /tmp/epdg-ca.key
sudo pki --self --ca --in /tmp/epdg-ca.key --type rsa --dn "CN=ePDG CA" --outform pem > /tmp/epdg-ca.crt
sudo pki --gen --type rsa --size 2048 --outform pem > /tmp/epdg.key
sudo pki --pub --in /tmp/epdg.key --type rsa | sudo pki --issue --cacert /tmp/epdg-ca.crt --cakey /tmp/epdg-ca.key --dn "CN=epdg.localdomain" --san epdg.localdomain --outform pem > /tmp/epdg.crt
sudo cp /tmp/epdg.key /etc/swanctl/private/epdg.key
sudo cp /tmp/epdg.crt /etc/swanctl/x509/epdg.crt
sudo cp /tmp/epdg-ca.crt /etc/swanctl/x509ca/epdg-ca.crt
```

## 4. 加载与启动

```bash
sudo systemctl restart strongswan-starter
sudo swanctl --load-all
sudo swanctl --list-conns
```

## 5. 快速检查

```bash
journalctl -t charon -n 100 --no-pager
```

关键成功特征：

- `received RADIUS Access-Challenge`
- `received RADIUS Access-Accept`
- `EAP method EAP_AKA succeeded, MSK established`
- `IKE_SA ... established`
- `CHILD_SA ... established`
