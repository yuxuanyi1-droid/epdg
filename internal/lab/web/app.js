/* ePDG Lab console.
 *
 * The whole UI is driven by SCHEMA below: each entry describes one configuration
 * section as a list of groups of fields, addressed by dotted path into the
 * deploy/lab.yaml document. Adding a parameter to lab.yaml means adding one
 * line here, which is what keeps the console honest as the lab grows.
 */
"use strict";

const SCHEMA = [
  {
    id: "network",
    num: "00",
    title: "网络与地址",
    note: "每个容器一个静态地址，必须落在网络前缀内，且不得与 UE 地址池重叠",
    groups: [
      {
        label: "网桥",
        fields: [
          { key: "network.name", label: "网桥名称", type: "text", width: 1 },
          { key: "network.subnet", label: "网桥前缀", type: "text", hint: "CIDR，例如 10.99.0.0/24" },
          { key: "network.host_address", label: "宿主侧地址", type: "text", hint: "IPsec 与基站所在宿主地址" },
        ],
      },
      {
        label: "节点地址",
        dynamic: "network.nodes",
        field: (name) => ({
          key: `network.nodes.${name}`,
          label: name,
          type: "text",
        }),
      },
    ],
  },
  {
    id: "plmn",
    num: "01",
    title: "PLMN 与订户",
    note: "IMS 域用三位 MNC，IMSI 与 Open5GS 用两位 MNC，两者不能混用",
    groups: [
      {
        label: "网络标识",
        fields: [
          { key: "plmn.mcc", label: "MCC", type: "text" },
          { key: "plmn.mnc", label: "MNC（两位）", type: "text", hint: "IMSI、Open5GS 使用" },
          { key: "plmn.mnc3", label: "MNC（三位）", type: "text", hint: "IMS 域使用，例如 ims.mnc001" },
        ],
      },
      {
        label: "订户与共享密钥",
        fields: [
          { key: "credentials.imsi", label: "IMSI", type: "text", hint: "15 位" },
          { key: "credentials.ki", label: "K", type: "text", hint: "32 位十六进制" },
          { key: "credentials.opc", label: "OPc", type: "text", hint: "32 位十六进制" },
          { key: "credentials.radius_secret", label: "RADIUS 共享密钥", type: "text" },
          { key: "credentials.kamailio_db_password", label: "Kamailio 数据库口令", type: "text", hint: "改动需重建数据库卷" },
        ],
      },
    ],
  },
  {
    id: "epdg",
    enabled: "epdg.enabled",
    num: "02",
    title: "ePDG",
    note: "SWu 数据面由宿主上的 strongSwan 承载，这里配置控制面与 AAA 链路",
    groups: [
      {
        label: "运行",
        fields: [
          { key: "epdg.enabled", label: "启用", type: "bool" },
          { key: "epdg.node_id", label: "节点标识", type: "text" },
          { key: "epdg.http.listen", label: "管理 API 监听", type: "text" },
        ],
      },
      {
        label: "IPsec（strongSwan）",
        fields: [
          { key: "epdg.ipsec.backend", label: "后端", type: "select", options: ["vici", "swanctl", "noop"] },
          { key: "epdg.ipsec.mode", label: "模式", type: "select", options: ["passive", "active"], hint: "SWu 下 UE 始终是发起方" },
          { key: "epdg.ipsec.socket", label: "VICI socket", type: "text" },
          { key: "epdg.ipsec.connection_name", label: "连接名", type: "text" },
          { key: "epdg.ipsec.child_name", label: "子 SA 名", type: "text" },
        ],
      },
      {
        label: "AAA 与 RADIUS",
        fields: [
          { key: "epdg.aaa.backend", label: "AAA 后端", type: "select", options: ["pyhss_api", "noop"] },
          { key: "epdg.aaa.origin_host", label: "Origin-Host", type: "text" },
          { key: "epdg.aaa.origin_realm", label: "Origin-Realm", type: "text" },
          { key: "epdg.aaa.destination_host", label: "HSS 主机", type: "text" },
          { key: "epdg.aaa.eap_max_rounds", label: "EAP 最大轮次", type: "number" },
          { key: "epdg.radius.backend", label: "RADIUS 后端", type: "select", options: ["eap_aka", "noop"] },
          { key: "epdg.radius.listen", label: "RADIUS 监听", type: "text" },
        ],
      },
      {
        label: "参考点",
        fields: [
          { key: "epdg.protocol.swu.local_address", label: "SWu 本地地址", type: "text" },
          { key: "epdg.protocol.swu.ike_port", label: "IKE 端口", type: "number" },
          { key: "epdg.protocol.swu.natt_port", label: "NAT-T 端口", type: "number" },
          { key: "epdg.protocol.s2b.backend", label: "S2b 后端", type: "select", options: ["gtpv2", "gtpv2_echo", "noop"] },
          { key: "epdg.protocol.s2b.local_address", label: "S2b 本地地址", type: "text" },
          { key: "epdg.protocol.s2b.apn", label: "S2b APN", type: "text" },
          { key: "epdg.protocol.s2b.timeout_seconds", label: "S2b 超时（秒）", type: "number" },
        ],
      },
      {
        label: "UE 内层地址池",
        fields: [
          { key: "epdg.ue_pool.subnet", label: "子网", type: "text" },
          { key: "epdg.ue_pool.gateway", label: "网关", type: "text" },
          { key: "epdg.ue_pool.range_start", label: "起始地址", type: "text" },
          { key: "epdg.ue_pool.range_end", label: "结束地址", type: "text" },
        ],
      },
    ],
  },
  {
    id: "open5gs",
    enabled: "open5gs.enabled",
    num: "03",
    title: "Open5GS EPC",
    note: "MME 面向基站，SGW/PGW 承载 S1-U 与 S2b；HSS/PCRF 默认由 PyHSS 提供",
    groups: [
      {
        label: "运行",
        fields: [
          { key: "open5gs.enabled", label: "启用", type: "bool" },
          { key: "open5gs.hss_backend", label: "HSS/PCRF 来源", type: "select", options: ["pyhss", "open5gs"], hint: "open5gs 需额外启用 MongoDB" },
          { key: "open5gs.gtpc_port", label: "GTP-C 端口", type: "number" },
          { key: "open5gs.pfcp_port", label: "PFCP 端口", type: "number" },
        ],
      },
      {
        label: "MME",
        fields: [
          { key: "open5gs.mme.mme_name", label: "MME 名称", type: "text" },
          { key: "open5gs.mme.mme_gid", label: "MME Group ID", type: "number" },
          { key: "open5gs.mme.mme_code", label: "MME Code", type: "number" },
          { key: "open5gs.mme.tac", label: "TAC", type: "number" },
          { key: "open5gs.mme.network_name_full", label: "网络名称（全）", type: "text" },
          { key: "open5gs.mme.network_name_short", label: "网络名称（短）", type: "text" },
          { key: "open5gs.mme.integrity_order", label: "完整性算法顺序", type: "list" },
          { key: "open5gs.mme.ciphering_order", label: "加密算法顺序", type: "list" },
        ],
      },
      {
        label: "SGW / 用户面",
        fields: [
          { key: "open5gs.sgw.gtpu_address", label: "SGW-U GTP-U 地址", type: "text" },
          { key: "open5gs.ue_pool.subnet", label: "UE 池子网", type: "text" },
          { key: "open5gs.ue_pool.gateway", label: "UE 池网关", type: "text" },
          { key: "open5gs.dns", label: "DNS", type: "list" },
        ],
      },
    ],
  },
  {
    id: "enb",
    enabled: "enb.enabled",
    num: "04",
    title: "基站（srsRAN eNB）",
    note: "真正跑起来需要 SDR 或 ZMQ 虚拟射频；只需配置参数时可以保持关闭",
    groups: [
      {
        label: "运行与身份",
        fields: [
          { key: "enb.enabled", label: "启用", type: "bool" },
          { key: "enb.enb_id", label: "eNB ID", type: "text", hint: "如 0x19B" },
          { key: "enb.mcc", label: "MCC", type: "text" },
          { key: "enb.mnc", label: "MNC", type: "text" },
          { key: "enb.tac", label: "TAC", type: "number" },
        ],
      },
      {
        label: "接口",
        fields: [
          { key: "enb.s1c_bind_address", label: "S1-C 绑定地址", type: "text" },
          { key: "enb.gtp_bind_address", label: "GTP-U 绑定地址", type: "text" },
        ],
      },
      {
        label: "射频",
        fields: [
          { key: "enb.device.name", label: "射频设备", type: "text" },
          { key: "enb.device.args", label: "设备参数", type: "text" },
          { key: "enb.n_prb", label: "PRB 数", type: "number", hint: "6/15/25/50/75/100" },
          { key: "enb.dl_earfcn", label: "DL EARFCN", type: "number" },
          { key: "enb.tx_gain", label: "TX 增益", type: "number" },
          { key: "enb.rx_gain", label: "RX 增益", type: "number" },
          { key: "enb.cipher_algo_pref", label: "加密算法偏好", type: "list" },
          { key: "enb.integ_algo_pref", label: "完整性算法偏好", type: "list" },
        ],
      },
    ],
  },
];

// ---------------------------------------------------------------- state

let lab = null;          // the whole lab.yaml document
let activeSection = SCHEMA[0].id;

// ---------------------------------------------------------------- utilities

const $ = (sel, root = document) => root.querySelector(sel);

function getPath(obj, path) {
  return path.split(".").reduce((acc, k) => (acc == null ? undefined : acc[k]), obj);
}

function setPath(obj, path, value) {
  const keys = path.split(".");
  const last = keys.pop();
  let cur = obj;
  for (const k of keys) {
    if (typeof cur[k] !== "object" || cur[k] === null) cur[k] = {};
    cur = cur[k];
  }
  cur[last] = value;
}

function clockNow() {
  return new Date().toLocaleTimeString("en-GB", { hour12: false });
}

function logTo(kind, text) {
  const box = $("#console");
  const line = document.createElement("div");
  line.className = `console__line console__line--${kind}`;
  const t = document.createElement("span");
  t.className = "console__time";
  t.textContent = clockNow();
  const b = document.createElement("span");
  b.className = "console__text";
  b.textContent = text;
  line.append(t, b);
  box.append(line);
  box.scrollTop = box.scrollHeight;
}

let toastTimer = null;
function toast(kind, text) {
  const el = $("#toast");
  el.className = `toast toast--${kind} toast--show`;
  el.textContent = text;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.className = `toast toast--${kind}`;
  }, 4200);
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { raw: text };
    }
  }
  return { ok: res.ok, status: res.status, payload };
}

// ---------------------------------------------------------------- rendering

function fieldLabel(field) {
  const wrap = document.createElement("span");
  wrap.className = "field__label";
  const name = document.createElement("span");
  name.textContent = field.label;
  wrap.append(name);
  if (field.hint) {
    const hint = document.createElement("span");
    hint.className = "field__hint";
    hint.textContent = field.hint;
    wrap.append(hint);
  }
  return wrap;
}

function buildControl(field) {
  const value = getPath(lab, field.key);
  let input;

  if (field.type === "bool") {
    const label = document.createElement("label");
    label.className = "switch";
    input = document.createElement("input");
    input.type = "checkbox";
    input.checked = Boolean(value);
    input.dataset.key = field.key;
    input.dataset.kind = "bool";
    const track = document.createElement("span");
    track.className = "switch__track";
    const text = document.createElement("span");
    track.className = "switch__track";
    text.className = "switch__text";
    text.textContent = input.checked ? "开启" : "关闭";
    input.addEventListener("change", () => {
      text.textContent = input.checked ? "开启" : "关闭";
    });
    label.append(input, track, text);
    return label;
  }

  if (field.type === "select") {
    input = document.createElement("select");
    for (const opt of field.options) {
      const o = document.createElement("option");
      o.value = opt;
      o.textContent = opt;
      input.append(o);
    }
    input.value = value ?? "";
  } else if (field.type === "number") {
    input = document.createElement("input");
    input.type = "number";
    input.value = value ?? 0;
  } else if (field.type === "list") {
    input = document.createElement("input");
    input.type = "text";
    input.value = Array.isArray(value) ? value.join(", ") : "";
    input.dataset.kind = "list";
  } else {
    input = document.createElement("input");
    input.type = "text";
    input.value = value ?? "";
  }

  input.dataset.key = field.key;
  input.dataset.kind = input.dataset.kind || field.type || "text";
  input.id = `f-${field.key.replace(/\./g, "-")}`;
  return input;
}

function buildField(field) {
  const wrap = document.createElement("div");
  wrap.className = "field";
  const control = buildControl(field);
  wrap.append(fieldLabel(field), control);
  return wrap;
}

function buildGroup(group) {
  const box = document.createElement("div");
  box.className = "group";
  const label = document.createElement("div");
  label.className = "group__label";
  label.textContent = group.label;
  box.append(label);

  const grid = document.createElement("div");
  grid.className = "fields";

  if (group.dynamic) {
    // Dynamic maps, such as network.nodes.<name>, get one field per key.
    const map = getPath(lab, group.dynamic) || {};
    for (const name of Object.keys(map)) {
      grid.append(buildField(group.field(name)));
    }
  } else {
    for (const field of group.fields) {
      grid.append(buildField(field));
    }
  }
  box.append(grid);
  return box;
}

function buildModule(section) {
  const mod = document.createElement("section");
  mod.className = "module";

  const head = document.createElement("div");
  head.className = "module__head";
  const id = document.createElement("span");
  id.className = "module__id";
  id.textContent = section.num;
  const title = document.createElement("h2");
  title.className = "module__title";
  title.textContent = section.title;
  head.append(id, title);
  if (section.note) {
    const note = document.createElement("span");
    note.className = "module__note";
    note.textContent = section.note;
    head.append(note);
  }

  const body = document.createElement("div");
  body.className = "module__body";
  for (const group of section.groups) body.append(buildGroup(group));

  mod.append(head, body);
  return mod;
}

function renderRail() {
  const rail = $("#rail");
  for (const old of rail.querySelectorAll(".rail__item")) {
    old.remove();
  }
  for (const section of SCHEMA) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "rail__item";
    btn.setAttribute("aria-current", String(section.id === activeSection));

    const num = document.createElement("span");
    num.className = "rail__num";
    num.textContent = section.num;

    const led = document.createElement("span");
    const enabled = section.enabled ? Boolean(getPath(lab, section.enabled)) : true;
    led.className = "led " + (enabled ? "led--on" : "led--off");

    const name = document.createElement("span");
    name.textContent = section.title;

    btn.append(num, led, name);
    btn.addEventListener("click", () => {
      collect();
      activeSection = section.id;
      renderAll();
    });
    rail.append(btn);
  }
}

function renderWorkspace() {
  const ws = $("#workspace");
  ws.textContent = "";
  const section =
    SCHEMA.find((s) => s.id === activeSection) ||
    ({ id: "none", title: "无", note: "选择左侧模块", groups: [] });
  ws.append(buildModule(section));
}

function renderMeta() {
  $("#meta-node").textContent = lab?.epdg?.node_id ?? "—";
  const p = lab?.plmn;
  $("#meta-plmn").textContent = p ? `${p.mcc}/${p.mnc}` : "—";
  $("#meta-subnet").textContent = lab?.network?.subnet ?? "—";
}

function renderAll() {
  renderRail();
  renderWorkspace();
  renderMeta();
}

// ---------------------------------------------------------------- editing

/** collect() reads every control back into the lab document. */
function collect() {
  const controls = $("#workspace").querySelectorAll("[data-key]");
  for (const control of controls) {
    const key = control.dataset.key;
    const kind = control.dataset.kind;
    let value;
    switch (kind) {
      case "bool":
        value = control.checked;
        break;
      case "number":
        value = Number(control.value);
        break;
      case "list":
        value = control.value
          .split(",")
          .map((v) => v.trim())
          .filter((v) => v.length > 0);
        break;
      default:
        value = control.value;
    }
    setPath(lab, key, value);
  }
}

// ---------------------------------------------------------------- actions

async function loadLab() {
  const { ok, payload } = await api("GET", "/api/v1/lab");
  if (!ok) {
    toast("err", "无法读取 lab.yaml");
    logTo("err", `GET /api/v1/lab 失败：${JSON.stringify(payload)}`);
    return;
  }
  lab = payload;
  renderAll();
  logTo("info", "已载入 deploy/lab.yaml");
  refreshStatus();
}

async function saveLab() {
  collect();
  const { ok, status, payload } = await api("PUT", "/api/v1/lab", lab);
  if (!ok) {
    toast("err", `保存被拒绝（HTTP ${status}）`);
    logTo("err", `保存失败：${payload?.error ?? JSON.stringify(payload)}`);
    markInvalidFields(payload?.error);
    return;
  }
  lab = payload.lab ?? lab;
  renderAll();
  toast("ok", "已写入 deploy/lab.yaml，点“生成配置”让容器读到改动");
  logTo("ok", "已保存 deploy/lab.yaml");
  refreshStatus();
}

/** markInvalidFields highlights inputs whose key is named in a validation error. */
function markInvalidFields(message) {
  for (const input of document.querySelectorAll("[data-key]")) {
    input.removeAttribute("aria-invalid");
  }
  if (!message) return;
  const keys = [...new Set(message.match(/[a-z_]+(\.[a-z0-9_]+)+/gi) || [])];
  for (const key of keys) {
    const input = document.querySelector(`[data-key="${CSS.escape(key)}"]`);
    if (input) input.setAttribute("aria-invalid", "true");
  }
}

async function renderConfigs() {
  collect();
  const save = await api("PUT", "/api/v1/lab", lab);
  if (!save.ok) {
    toast("err", `先保存失败（HTTP ${save.status}）`);
    logTo("err", `保存失败：${save.payload?.error ?? ""}`);
    markInvalidFields(save.payload?.error);
    return;
  }
  lab = save.payload.lab ?? lab;

  const { ok, payload } = await api("POST", "/api/v1/render");
  if (!ok) {
    toast("err", "生成配置失败");
    logTo("err", `生成失败：${payload?.error ?? ""}`);
    return;
  }
  toast("ok", `已生成 ${payload.files.length} 个配置文件`);
  logTo("ok", `生成完成：${payload.env}，profiles=[${payload.profiles.join(",")}]`);
  for (const f of payload.files) logTo("info", `  ${f}`);
  logTo("warn", "容器需要重启才会读取新配置：make lab-up");
  renderAll();
  refreshStatus();
}

async function refreshStatus() {
  const { ok, payload } = await api("GET", "/api/v1/render/status");
  const pill = $("#status-render");
  if (!ok) {
    pill.className = "pill pill--err";
    pill.textContent = "状态不可用";
    return;
  }
  if (payload.render_required) {
    pill.className = "pill pill--warn";
    pill.textContent = "配置待生成";
    pill.title = `lab.yaml 于 ${payload.lab_modified} 修改，晚于最近一次生成`;
  } else {
    pill.className = "pill pill--ok";
    pill.textContent = "配置已生成";
    pill.title = `最近生成：${payload.rendered_at || "未知"}`;
  }
}

// ---------------------------------------------------------------- wiring

$("#btn-reload").addEventListener("click", () => {
  logTo("info", "重新载入 lab.yaml（未保存的改动将丢失）");
  loadLab();
});
$("#btn-save").addEventListener("click", saveLab);
$("#btn-render").addEventListener("click", renderConfigs);

// Warn before losing unsaved edits on a reload.
window.addEventListener("beforeunload", (e) => {
  e.preventDefault();
  e.returnValue = "";
});

loadLab();
