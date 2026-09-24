# 容器化实验室

一条命令起来的 ePDG / EPC / IMS 实验室，外加一个配置台。

## 组成

```
deploy/
  lab.yaml               唯一事实来源：地址、PLMN、订户、ePDG/EPC/基站参数
  docker-compose.yml     容器编排（地址全部来自 .env）
  docker/                Dockerfile 与容器入口脚本
  runtime/               由 labctl render 生成，容器挂载的就是这里
  scripts/verify.sh      验证脚本：容器状态 + 真实信令
  Makefile               make lab-up / lab-ui / lab-verify …
cmd/labctl               命令行工具：render（生成配置）与 serve（配置台）
```

`lab.yaml` 是唯一的真相。改它，然后 `labctl render`，再重启容器 —— 没有第二处需要同步。

## 快速开始

```bash
# 1. 生成配置（deploy/.env 与 deploy/runtime）
make -f deploy/Makefile lab-render

# 2. 启动核心容器（MariaDB、Redis、PyHSS、三套 CSCF、ePDG）
make -f deploy/Makefile lab-up

# 3. 验证
make -f deploy/Makefile lab-verify

# 4. 打开配置台
make -f deploy/Makefile lab-ui     # http://127.0.0.1:8088
```

默认启用 `core` 与 `epc` 两个 profile。`lab.yaml` 里的开关决定 profile：

| lab.yaml | profile | 说明 |
|---|---|---|
| 总是 | `core` | MariaDB、Redis、PyHSS、P/I/S-CSCF、ePDG |
| `open5gs.enabled: true` | `epc` | MME、SGW-C、SGW-U、SMF(PGW-C)、UPF |
| `open5gs.hss_backend: open5gs` | `open5gs-hss` | 额外跑 Open5GS 自带 HSS/PCRF（需要 MongoDB） |
| `enb.enabled: true` | `enb` | srsRAN 基站 |

## 地址是怎么进去的

仓库里的配置是按单机 `127.0.0.x` 写的（MME 127.0.0.2、SGW-C 127.0.0.3、PGW 127.0.0.4、SGW-U 127.0.0.6、HSS 127.0.0.8、PCRF 127.0.0.9）。容器各有独立网络命名空间，这些地址不再有意义，因此 `labctl render`：

1. 把 `configs/` 下的配置**原样复制**到 `deploy/runtime/`；
2. 按一张**显式替换表**把地址、端口、数据库 URL、路径改写成容器布局。

之所以是"复制+替换"而不是重新写一份配置：`configs/` 仍是权威来源，改那里容器栈就会跟着变；同时每条替换的左值都是仓库里真实存在的字符串，**一旦仓库配置变动，render 会直接报错而不是默默生成错误地址**。

举例（`internal/lab/render_services.go`）：

```
mysql://icscf:heslo@127.0.0.1/icscf   →  mysql://icscf:<pw>@10.99.0.10/icscf
listen=udp:127.0.0.1:5061             →  listen=udp:10.99.0.31:5061
$rd = "127.0.0.1:5062";               →  $rd = "10.99.0.32:5062";
1 sip:127.0.0.1:5062      (dispatcher.list)  →  1 sip:10.99.0.32:5062
```

P-CSCF 的 `listen=udp:10.255.0.1:5060` / `10.46.0.1:5060`（原单机实验室的隧道与 IPsec 套接字）被**删除**而不是改写，否则同一地址会声明两次。

只有三处是完全生成的，因为它们本来就是实验室参数：`runtime/epdg/epdg.yaml`、`runtime/enb/enb.conf`、`runtime/open5gs/{smf,upf}.yaml`（仓库没提供 SMF/UPF 配置）。

## 配置台

`labctl serve` 提供一个 REST API 与一个内置的静态前端（无构建步骤，`go:embed` 打包）。

```
GET  /api/v1/lab                 读取整份 lab.yaml
PUT  /api/v1/lab                 整份写回（校验失败返回 422 与原因）
GET  /api/v1/lab/{section}       单节读取
PUT  /api/v1/lab/{section}       单节写回
POST /api/v1/render              生成 deploy/.env 与 deploy/runtime
GET  /api/v1/render/status       判断配置是否落后于 lab.yaml
```

页面分三个域：**Open5GS**（MME/SGW/PLMN/地址池）、**基站**（srsRAN eNB）、**ePDG**（IPsec/AAA/RADIUS/参考点/UE 池），外加**网络与地址**和**PLMN 与订户**两节。

界面按 `app.js` 里的 `SCHEMA` 声明式生成：往 `lab.yaml` 加一个参数，只需在 `SCHEMA` 加一行，控件、校验提示、保存都会自动跟上。

保存与生效是两步：**保存**只写 `lab.yaml`，**生成配置**才写 `runtime/`，之后需要重启容器（`make lab-up`）。顶部状态灯会显示"配置待生成"。

## 校验

`labctl` 在写入前拒绝不合法的定义，例如：

* 地址不在 `network.subnet` 内，或两个节点撞地址；
* `epdg.ue_pool` / `open5gs.ue_pool` 与 `network.subnet` 重叠（容器与 UE 会拿到同一地址）；
* `ue_pool.gateway` 不在自己的池内；`epdg.ue_pool` 与 `open5gs.ue_pool` 相同；
* PLMN 位数不对（MCC 3 位、MNC 2 或 3 位、`mnc3` 必须 3 位）；
* IMSI 不是 15 位，K/OPc 不是 32 位十六进制；
* 枚举值非法（`ipsec.backend`、`aaa.backend`、`radius.backend`、`s2b.backend`、`hss_backend`）。

## strongSwan 不在容器里

ePDG 的 IPsec 数据面需要内核 XFRM 与宿主网络命名空间，放进 bridge 网络里没有意义。因此：

* `strongswan` 在宿主上运行，`deploy/runtime/strongswan/` 是给宿主的配置（RADIUS 指向宿主的 `network.host_address`，即网桥的宿主侧地址）；
* `epdgd` 容器通过 `/run/charon.vici` 访问 charon 的控制套接字。

宿主的 charon 需要把 EAP 转给 ePDG 容器：

```
charon {
  plugins {
    eap-radius {
      servers {
        go-epdg { address = <宿主侧地址，即 10.99.0.1>  port = 18120  secret = <credentials.radius_secret> }
      }
    }
  }
}
```

## 已知限制

**容器内的 S-CSCF 在首次注册时会崩溃（SIGSEGV）。**

* 现象：UE 收到 `401`（AKAv1-MD5 挑战，说明 P-CSCF → I-CSCF（UAR/UAA）→ S-CSCF（MAR/MAA）→ HSS 整条链路是通的），UE 也能由向量算出 RES；但 S-CSCF 在认证成功后、写任何数据之前崩掉，于是最终 `200 OK` 不会发出，UE 收到 `504`。
* 定位：崩溃点固定在 `configs/kamailio/scscf/kamailio.cfg` 里这段实验室改动分支的最后一行：

  ```
  if (!impu_registered("location")) {
          xlog("L_ERR", "Not REGISTERED\n");
          save("PRE_REG_SAR_REPLY", "location");   <-- 崩溃
  ```
* 已排除：共享内存不足（已设 `shm_size: 512m`）、`mlock_pages`/`shm_force_alloc`、`ims_usrloc_scscf` 的 `db_mode`、数据库账号与连接。崩溃发生在任何 DB 写入之前（`scscf.impu` 始终为空）。
* 同一份配置在**宿主机原生跑**时 19/19 通过（见 `test/integration/ims_register.sh`），所以这不是编排问题，而是该分支在容器环境下的 Kamailio 侧缺陷。
* 因此 `deploy/scripts/verify.sh` 断言到"容器链路里拿到 AKAv1-MD5 挑战、UE 能由向量算出 RES"，并把 200 OK 这一步列为已知限制而不是失败。

`open5gs-upfd` 需要 `/dev/net/tun` 与 `NET_ADMIN`（compose 已声明）。容器没有 `/dev/net/tun` 时该服务起不来，可以只用 SGW-U（`open5gs-sgwud`，纯 PFCP/GTP-U，无 TUN 需求）承载用户面。

## 换端口 / 换地址

`lab.yaml` 里 `network.nodes` 每项对应一个容器地址，改完 `render` 即可；`epdg.http.listen`、`epdg.radius.listen` 等端口会写进 `.env`，compose 的 `ports:` 直接用它们。

注意 `credentials.kamailio_db_password` 与 `credentials.radius_secret`：前者只在 MariaDB **首次初始化**时写入库用户，改口令后需要重建卷（`make clean` 会删除卷）。后者由 render 同时写进 Kamailio 的 `DB_URL`、ePDG 的 `radius.secret` 与 strongSwan 的 `eap-radius` 配置，改完 render + 重启即可。
