# ePDG 部署（Go 控制面）

## 1. 依赖

- Go 1.24 或更高版本
- strongSwan（`charon` + `swanctl`），需启用 `vici`、`kernel-netlink`、`eap-radius`、
  `eap-aka` 与 `fips-prf` 插件

  > `eap-aka` 的 `EAP_SERVER:AKA` / `EAP_CLIENT:AKA` 特性依赖 `PRF:PRF_FIPS_SHA1_160`，
  > 对应的 `fips-prf` 插件必须存在，否则 EAP-AKA 被静默禁用。

- PyHSS（`pyhss/`）及其 Python 依赖，提供 AKA 五元组 API

## 2. 构建

```bash
go build -o epdgd ./cmd/epdgd
```

## 3. 配置

可用配置：

- `configs/epdg/epdg.yaml`：标准运行配置
- `configs/epdg/epdg.std.yaml`：标准模板
- `configs/epdg/epdg.dev.yaml`：开发调试（全部 noop）

关键字段：

- `ipsec.backend: vici`（推荐）或 `swanctl`；`ipsec.socket` 指向 charon 的 VICI socket
- `ipsec.mode: passive`：SWu 场景下 UE 始终是 IKEv2 发起方
- `aaa.backend: pyhss_api`，`aaa.pyhss_api.base_url` 指向 PyHSS
- `aaa.pyhss_api.vector_path_template`：必须指向返回完整五元组的端点
- `radius.backend: eap_aka`，`radius.listen` / `radius.secret` 必须与 strongSwan
  `eap-radius` 插件的 servers 配置一致

## 4. strongSwan 侧配置

`strongswan.conf` 中需要把 EAP 转给本 ePDG：

```conf
charon {
  plugins {
    vici {
      socket = unix:///run/charon.vici
    }
    eap-radius {
      nas_identifier = epdg.local
      servers {
        go-epdg {
          address = 127.0.0.1
          port = 18120
          secret = pyhss-radius-secret
        }
      }
    }
  }
}
```

`swanctl.conf` 中 responder 连接的 `remote.auth` 使用 `eap-radius`：

```conf
connections {
  epdg-ike {
    version = 2
    local_addrs = <ePDG IP>
    proposals = aes128-sha1-modp2048
    pools = ue_pool
    local { auth = pubkey  certs = epdg.crt  id = epdg.local }
    remote { auth = eap-radius }
    children {
      ue-default {
        local_ts = <内层网段>
        remote_ts = dynamic
        esp_proposals = aes128-sha1
        start_action = trap
      }
    }
  }
}
pools {
  ue_pool { addrs = 10.46.0.100-10.46.0.200  dns = 8.8.8.8 }
}
```

`remote_ts = dynamic` 会让 charon 要求 UE 通过 IKEv2 配置载荷申请地址，UE 侧需要设置
`vips = 0.0.0.0`。

## 5. 启动

```bash
./epdgd -config configs/epdg/epdg.yaml -log-level info
```

## 6. 健康检查

默认监听 `:19090`：

```bash
curl -s http://127.0.0.1:19090/healthz
curl -s http://127.0.0.1:19090/v1/compliance/check
```

就绪检查会真实探测：PyHSS `/oam/ping`、charon（VICI `version`）、RADIUS 监听端口、S2b 对端
（`gtpv2_echo` 时才发 Echo）。配置为 `noop` 的组件按“已按配置禁用”处理。

## 7. 说明

epdgd 负责 EAP-AKA 认证、会话编排与 S2b 信令，不替代 strongSwan 的 IKE/IPsec 数据面实现。
`internal/ipsec` 通过 VICI 直接调用 charon，不再依赖 `swanctl` CLI（`swanctl` 后端仍保留）。
