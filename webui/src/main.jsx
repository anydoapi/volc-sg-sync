import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  Boxes,
  Check,
  ChevronRight,
  CircleAlert,
  CloudCog,
  Copy,
  Database,
  ExternalLink,
  Filter,
  Gauge,
  KeyRound,
  LayoutDashboard,
  Loader2,
  LockKeyhole,
  LogIn,
  Menu,
  Network,
  RefreshCw,
  Search,
  Settings2,
  Shield,
  SquareStack,
  Terminal,
  Trash2,
  UserRound,
  X,
  Zap,
} from "lucide-react";
import "./styles.css";

const navItems = [
  { id: "overview", label: "概览", icon: LayoutDashboard },
  { id: "targets", label: "同步计划", icon: Zap },
  { id: "instances", label: "实例资产", icon: Boxes },
  { id: "groups", label: "安全组", icon: Shield },
  { id: "settings", label: "控制台设置", icon: Settings2 },
];

const emptyPlan = {
  mode: "automatic",
  current_cidr: "",
  previous_cidr: "",
  replacement: "",
  match: "",
  rule_count: 0,
  group_count: 0,
  target_count: 0,
  interval: "2h（默认）",
  schedule_times: ["09:00", "18:00"],
  next_check_at: "",
};

function readCookie(name) {
  const value = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${name}=`));
  return value ? decodeURIComponent(value.split("=").slice(1).join("=")) : "";
}

async function api(path, options = {}) {
  const headers = {
    ...(options.headers || {}),
    "X-CSRF-Token": readCookie("volc_csrf"),
  };
  const response = await fetch(path, { ...options, headers });
  let data = {};
  try {
    data = await response.json();
  } catch {
    /* empty response */
  }
  if (!response.ok)
    throw new Error(data.error || `请求失败（${response.status}）`);
  return data;
}

function cn(...values) {
  return values.filter(Boolean).join(" ");
}

function Button({
  variant = "outline",
  size = "md",
  className,
  children,
  ...props
}) {
  return (
    <button
      className={cn("btn", `btn-${variant}`, `btn-${size}`, className)}
      {...props}
    >
      {children}
    </button>
  );
}

function Badge({ children, tone = "neutral" }) {
  return <span className={cn("badge", `badge-${tone}`)}>{children}</span>;
}

function Card({ className, children }) {
  return <section className={cn("card-panel", className)}>{children}</section>;
}

function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}

function Modal({ title, onClose, children, wide = false }) {
  useEffect(() => {
    const onKey = (event) => event.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [onClose]);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(event) => event.target === event.currentTarget && onClose()}
    >
      <div className={cn("modal", wide && "modal-wide")}>
        <div className="modal-head">
          <h2>{title}</h2>
          <Button size="icon" onClick={onClose}>
            <X size={17} />
          </Button>
        </div>
        {children}
      </div>
    </div>
  );
}

function StatCard({ label, value, detail, icon: Icon, tone = "blue" }) {
  return (
    <div className="stat-card">
      <div className={cn("stat-icon", `tone-${tone}`)}>
        <Icon size={18} />
      </div>
      <div>
        <div className="stat-label">{label}</div>
        <div className="stat-value">{value}</div>
        <div className="stat-detail">{detail}</div>
      </div>
    </div>
  );
}

function App() {
  const [page, setPage] = useState("overview");
  const [status, setStatus] = useState({
    rule_count: 0,
    running: false,
    dry_run: false,
  });
  const [plan, setPlan] = useState(emptyPlan);
  const [targets, setTargets] = useState([]);
  const [inventory, setInventory] = useState({ instances: [], groups: [] });
  const [events, setEvents] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [config, setConfig] = useState({
    ip_providers: [],
    interval: "2h",
    schedule_times: [],
    web_listen: "127.0.0.1:12345",
    dry_run: false,
  });
  const [message, setMessage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const [ruleGroup, setRuleGroup] = useState(null);

  const notify = (text, tone = "success") => {
    setMessage({ text, tone });
    window.setTimeout(() => setMessage(null), 4200);
  };
  const refreshStatus = async () => {
    try {
      setStatus(await api("/api/status"));
    } catch (error) {
      notify(error.message, "error");
    }
  };
  const refreshPlan = async () => {
    try {
      setPlan({ ...emptyPlan, ...(await api("/api/sync-plan")) });
    } catch (error) {
      notify(error.message, "error");
    }
  };
  const refreshTargets = async () => {
    try {
      setTargets((await api("/api/targets")) || []);
    } catch (error) {
      notify(error.message, "error");
    }
  };
  const refreshInventory = async () => {
    try {
      setInventory(await api("/api/inventory"));
    } catch (error) {
      notify(error.message, "error");
    }
  };
  const refreshEvents = async () => {
    try {
      setEvents((await api("/api/events")) || []);
    } catch (error) {
      notify(error.message, "error");
    }
  };
  const refreshJobs = async () => {
    try {
      setJobs((await api("/api/jobs")) || []);
    } catch (error) {
      notify(error.message, "error");
    }
  };
  const refreshConfig = async () => {
    try {
      const next = await api("/api/config");
      setConfig((current) => ({ ...current, ...next }));
    } catch (error) {
      notify(error.message, "error");
    }
  };
  const refreshAll = async () => {
    setLoading(true);
    await Promise.all([
      refreshStatus(),
      refreshInventory(),
      refreshEvents(),
      refreshJobs(),
      refreshConfig(),
    ]);
    await refreshPlan();
    await refreshTargets();
    setLoading(false);
  };

  useEffect(() => {
    refreshAll();
    const timer = window.setInterval(() => {
      refreshStatus();
      refreshPlan();
      refreshJobs();
    }, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const navigate = (id) => {
    setPage(id);
    setMobileOpen(false);
    if (id === "targets") {
      refreshTargets();
      refreshPlan();
    }
    if (id === "groups" || id === "instances") refreshInventory();
  };
  const currentIP = plan.current_cidr || "检测中";
  const lastRun = status.last_run
    ? new Date(status.last_run).toLocaleString()
    : "尚未执行";

  return (
    <div className="app-shell">
      <aside className={cn("sidebar", mobileOpen && "sidebar-open")}>
        <div className="brand">
          <div className="brand-mark">
            <Network size={18} />
          </div>
          <div>
            <strong>火山同步</strong>
            <span>公网 IP 安全组管理</span>
          </div>
          <Button
            size="icon"
            className="mobile-close"
            onClick={() => setMobileOpen(false)}
          >
            <X size={17} />
          </Button>
        </div>
        <div className="nav-caption">资源管理</div>
        <nav>
          {navItems.slice(0, 4).map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={cn("nav-item", page === id && "nav-active")}
              onClick={() => navigate(id)}
            >
              <Icon size={17} />
              <span>{label}</span>
              {page === id && <ChevronRight size={14} className="nav-arrow" />}
            </button>
          ))}
        </nav>
        <div className="nav-caption">系统</div>
        <nav>
          <button
            className={cn("nav-item", page === "settings" && "nav-active")}
            onClick={() => navigate("settings")}
          >
            <Settings2 size={17} />
            <span>控制台设置</span>
          </button>
        </nav>
        <div className="sidebar-foot">
          <div className="secure-note">
            <LockKeyhole size={14} />
            <span>本机安全连接</span>
          </div>
          <span className="version">Web UI · React</span>
        </div>
      </aside>
      {mobileOpen && (
        <div className="mobile-scrim" onClick={() => setMobileOpen(false)} />
      )}
      <main className="main-shell">
        <header className="topbar">
          <div className="topbar-left">
            <Button
              size="icon"
              className="mobile-menu"
              onClick={() => setMobileOpen(true)}
            >
              <Menu size={18} />
            </Button>
            <div>
              <div className="eyebrow">
                控制台 /{" "}
                {navItems.find((item) => item.id === page)?.label || "概览"}
              </div>
              <h1>
                {navItems.find((item) => item.id === page)?.label || "概览"}
              </h1>
            </div>
          </div>
          <div className="topbar-actions">
            <div className="live-status">
              <span
                className={cn("live-dot", status.running && "live-running")}
              />
              {status.running ? "同步执行中" : "服务在线"}
            </div>
            <Button onClick={() => setLoginOpen(true)}>
              <LogIn size={15} />
              登录
            </Button>
            <Button
              variant="primary"
              disabled={status.running}
              onClick={async () => {
                try {
                  await api("/api/sync", { method: "POST", body: "{}" });
                  notify("同步任务已启动");
                  refreshStatus();
                } catch (error) {
                  notify(error.message, "error");
                }
              }}
            >
              <Zap size={15} />
              立即同步
            </Button>
            <div className="avatar">
              <UserRound size={16} />
            </div>
          </div>
        </header>
        <div className="page-content">
          {message && (
            <div className={cn("toast", `toast-${message.tone}`)}>
              {message.tone === "error" ? (
                <CircleAlert size={16} />
              ) : (
                <Check size={16} />
              )}
              {message.text}
              <button onClick={() => setMessage(null)}>
                <X size={14} />
              </button>
            </div>
          )}
          {page === "overview" && (
            <Overview
              status={status}
              plan={plan}
              events={events}
              currentIP={currentIP}
              lastRun={lastRun}
              onNavigate={navigate}
            />
          )}
          {page === "targets" && (
            <Targets
              targets={targets}
              setTargets={setTargets}
              plan={plan}
              currentIP={currentIP}
              inventory={inventory}
              onRefresh={() => {
                refreshTargets();
                refreshPlan();
              }}
              notify={notify}
              jobs={jobs}
              onJobsRefresh={refreshJobs}
            />
          )}
          {page === "instances" && (
            <Instances inventory={inventory} onRefresh={refreshInventory} />
          )}
          {page === "groups" && (
            <Groups
              inventory={inventory}
              onRefresh={refreshInventory}
              onOpen={setRuleGroup}
            />
          )}
          {page === "settings" && (
            <Settings
              config={config}
              setConfig={setConfig}
              onRefresh={refreshConfig}
              notify={notify}
            />
          )}
        </div>
      </main>
      {loginOpen && (
        <LoginModal
          onClose={() => setLoginOpen(false)}
          onSuccess={() => {
            setLoginOpen(false);
            notify("登录成功");
            refreshAll();
          }}
          onError={(error) => notify(error.message, "error")}
        />
      )}
      {ruleGroup && (
        <RuleDrawer
          group={ruleGroup}
          onClose={() => setRuleGroup(null)}
          onChanged={refreshInventory}
          notify={notify}
        />
      )}
    </div>
  );
}

function Overview({ status, plan, events, currentIP, lastRun, onNavigate }) {
  return (
    <div className="view">
      <div className="view-heading">
        <div>
          <div className="eyebrow">实时运行概览</div>
          <h2>把出口 IP 变化变成可追踪的规则变更</h2>
          <p>自动发现安全组，按计划检查公网出口，并在变更时安全替换白名单。</p>
        </div>
        <Button variant="primary" onClick={() => onNavigate("targets")}>
          <Zap size={15} />
          查看同步计划
        </Button>
      </div>
      <div className="stats-grid">
        <StatCard
          label="当前公网 IP"
          value={currentIP.replace("/32", "")}
          detail="多源一致性校验"
          icon={Network}
          tone="blue"
        />
        <StatCard
          label="同步规则"
          value={plan.rule_count || status.rule_count || 0}
          detail={`${plan.group_count || 0} 个安全组涉及`}
          icon={Shield}
          tone="green"
        />
        <StatCard
          label="任务状态"
          value={
            status.running ? "执行中" : status.last_error ? "失败" : "空闲"
          }
          detail={`上次执行：${lastRun}`}
          icon={Activity}
          tone={status.last_error ? "red" : "amber"}
        />
        <StatCard
          label="定时计划"
          value={(plan.schedule_times || ["09:00", "18:00"]).join(" / ")}
          detail={status.dry_run ? "预演模式" : "安全模式"}
          icon={Gauge}
          tone="violet"
        />
      </div>
      <div className="overview-grid">
        <Card>
          <div className="card-head">
            <div>
              <h3>自动同步计划</h3>
              <span>当前真实生效范围</span>
            </div>
            <Button size="sm" onClick={() => onNavigate("targets")}>
              管理计划 <ChevronRight size={14} />
            </Button>
          </div>
          <PlanSummary plan={plan} />
        </Card>
        <Card>
          <div className="card-head">
            <div>
              <h3>最近变更</h3>
              <span>最多显示最近 8 条审计记录</span>
            </div>
            <Database size={17} className="muted-icon" />
          </div>
          <EventTable events={events.slice(0, 8)} />
        </Card>
      </div>
    </div>
  );
}

function PlanSummary({ plan }) {
  const changed =
    plan.previous_cidr &&
    plan.current_cidr &&
    plan.previous_cidr !== plan.current_cidr;
  return (
    <div className="plan-summary">
      <div className="flow-row">
        <div className="flow-node">
          <span>旧 IP / 网段</span>
          <strong>{plan.previous_cidr || "尚无历史 IP"}</strong>
        </div>
        <div className="flow-arrow">
          <ChevronRight size={18} />
          <span>{changed ? "检测到变化" : "等待变化"}</span>
        </div>
        <div className="flow-node flow-current">
          <span>未来替换为</span>
          <strong>{plan.replacement || "当前出口 IP"}</strong>
        </div>
      </div>
      <div className="plan-meta">
        <span>
          <Filter size={14} />
          匹配：{plan.match || "首次运行仅新增当前 IP"}
        </span>
        <span>
          <Shield size={14} />
          涉及 {plan.group_count || 0} 个安全组 / {plan.rule_count || 0} 条规则
        </span>
        <span>
          <RefreshCw size={14} />
          每天 {(plan.schedule_times || ["09:00", "18:00"]).join("、")} 检查
        </span>
      </div>
    </div>
  );
}

function EventTable({ events }) {
  if (!events.length)
    return (
      <div className="empty-state">
        <Database size={22} />
        <span>暂无同步记录</span>
      </div>
    );
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>时间</th>
            <th>动作</th>
            <th>旧值</th>
            <th>新值</th>
            <th>结果</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>{new Date(event.occurred_at).toLocaleString()}</td>
              <td>{event.action === "replace" ? "替换" : event.action}</td>
              <td className="mono">{event.old_cidr || "-"}</td>
              <td className="mono">{event.new_cidr || "-"}</td>
              <td>
                <Badge tone={event.success ? "green" : "red"}>
                  {event.success ? "成功" : "失败"}
                </Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PlanCards({ plan }) {
  const items = [
    ["运行模式", plan.mode === "targets" ? "已保存目标" : "自动发现"],
    ["当前出口 IP", plan.current_cidr || "检测失败"],
    ["旧值（将被替换）", plan.previous_cidr || "尚无历史 IP"],
    ["未来替换为", plan.replacement || "等待检测"],
    ["匹配范围", plan.match || "首次运行仅新增当前 IP"],
    ["涉及规则", `${plan.rule_count || 0} 条`],
    ["涉及安全组", `${plan.group_count || 0} 个`],
    [
      "检测计划",
      `每天 ${(plan.schedule_times || ["09:00", "18:00"]).join(" / ")}`,
    ],
    [
      "下次检测",
      plan.next_check_at
        ? new Date(plan.next_check_at).toLocaleString()
        : "等待调度",
    ],
  ];
  return (
    <div className="plan-cards">
      {items.map(([label, value]) => (
        <div className="plan-card" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function Targets({
  targets,
  setTargets,
  plan,
  currentIP,
  inventory,
  onRefresh,
  notify,
  jobs,
  onJobsRefresh,
}) {
  const [oldIP, setOldIP] = useState("");
  const [newIP, setNewIP] = useState("");
  const [mode, setMode] = useState("contains");
  const [query, setQuery] = useState("");
  const [group, setGroup] = useState("");
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState([]);
  const [selectedPreview, setSelectedPreview] = useState(new Set());
  const filtered = targets.filter(
    (target) =>
      (!group || target.security_group_id === group) &&
      (!query ||
        `${target.name} ${target.security_group_id} ${target.note}`
          .toLowerCase()
          .includes(query.toLowerCase())),
  );
  const groups = [
    ...new Set(
      targets.map((target) => target.security_group_id).filter(Boolean),
    ),
  ];
  const updateTarget = (index, patch) =>
    setTargets((current) =>
      current.map((target, i) =>
        i === index ? { ...target, ...patch } : target,
      ),
    );
  const previewMatch = async () => {
    if (!oldIP.trim()) return notify("请先填写旧 IP 或网段", "error");
    setBusy(true);
    try {
      const result = await api("/api/rules/preview-match", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ match: oldIP.trim(), mode }),
      });
      setPreview(result.rules || []);
      setSelectedPreview(new Set((result.rules || []).map((rule) => rule.key)));
      notify(
        `已找到 ${result.count || 0} 条规则，默认全部选中，请确认后加入队列`,
      );
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setBusy(false);
    }
  };
  const bulkSync = async () => {
    if (!preview.length) return previewMatch();
    const skip = preview
      .filter((rule) => !selectedPreview.has(rule.key))
      .map((rule) => rule.key);
    if (!selectedPreview.size) return notify("至少选择一条规则", "error");
    setBusy(true);
    try {
      const result = await api("/api/rules/sync-by-match", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          match: oldIP.trim(),
          mode,
          new_cidr: newIP.trim(),
          skip,
        }),
      });
      notify(
        `已加入同步队列：${selectedPreview.size} 条规则，目标 ${result.new_cidr}`,
      );
      setPreview([]);
      setSelectedPreview(new Set());
      onJobsRefresh();
      onRefresh();
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setBusy(false);
    }
  };
  const saveTargets = async () => {
    try {
      await api("/api/targets", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(targets),
      });
      notify("同步目标已保存");
      onRefresh();
    } catch (error) {
      notify(error.message, "error");
    }
  };
  const importRules = async () => {
    const existing = new Set(targets.map((target) => target.name));
    const additions = [];
    inventory.groups.forEach((securityGroup) =>
      securityGroup.rules
        .filter((rule) => !rule.direction || rule.direction === "ingress")
        .forEach((rule, index) => {
          const base = `${securityGroup.name || securityGroup.id}-${rule.protocol}-${rule.port_start}-${rule.port_end}`;
          let name = base;
          let n = 2;
          while (existing.has(name)) name = `${base}-${n++}`;
          existing.add(name);
          additions.push({
            name,
            group: securityGroup.name || "",
            note: rule.description || "",
            region: securityGroup.region,
            security_group_id: securityGroup.id,
            protocol: rule.protocol,
            port_start: rule.port_start,
            port_end: rule.port_end,
            priority: rule.priority || 1,
            enabled: true,
            ip_match: oldIP.trim(),
            ip_match_mode: mode,
          });
        }),
    );
    setTargets((current) => [...current, ...additions]);
    notify(`已导入 ${additions.length} 条规则，请点击保存目标`);
  };
  return (
    <div className="view">
      <div className="view-heading">
        <div>
          <div className="eyebrow">规则编排</div>
          <h2>同步计划</h2>
          <p>先看清自动计划，再按需对历史 IP 做一次性批量替换。</p>
        </div>
        <Button onClick={onRefresh}>
          <RefreshCw size={15} />
          刷新计划
        </Button>
      </div>
      <Card className="plan-panel">
        <div className="card-head">
          <div>
            <h3>自动同步计划</h3>
            <span>系统会把命中旧值的入方向规则替换为当前出口 IP。</span>
          </div>
          <Badge tone={plan.mode === "targets" ? "blue" : "green"}>
            {plan.mode === "targets" ? "按已保存目标" : "自动发现"}
          </Badge>
        </div>
        <PlanCards plan={plan} />
        <div className="plan-callout">
          <Zap size={16} />
          <span>
            {plan.previous_cidr &&
            plan.current_cidr &&
            plan.previous_cidr !== plan.current_cidr
              ? `检测到出口变化：${plan.previous_cidr} → ${plan.current_cidr}，下一次自动同步将处理上方 ${plan.rule_count || 0} 条规则。`
              : `当前出口为 ${currentIP}，IP 未变化时不会重复修改规则。`}
          </span>
        </div>
      </Card>
      <Card>
        <div className="card-head">
          <div>
            <h3>按旧 IP / 网段立即同步</h3>
            <span>
              输入 `39.181.0.0` 也会按前两段匹配；留空新值则使用当前出口 IP。
            </span>
          </div>
          <Badge tone="amber">高影响操作</Badge>
        </div>
        <div className="sync-form">
          <Field label="旧 IP / 网段" hint="例如 39.181.0.0、39.181.0.0/16">
            <input
              value={oldIP}
              onChange={(event) => setOldIP(event.target.value)}
              placeholder="39.181.0.0"
            />
          </Field>
          <Field label="匹配方式">
            <select
              value={mode}
              onChange={(event) => setMode(event.target.value)}
            >
              <option value="contains">包含（推荐）</option>
              <option value="exact">精确</option>
              <option value="cidr">网段</option>
              <option value="prefix">前缀</option>
            </select>
          </Field>
          <Field label="替换为" hint={`留空使用当前出口 IP：${currentIP}`}>
            <input
              value={newIP}
              onChange={(event) => setNewIP(event.target.value)}
              placeholder={currentIP}
            />
          </Field>
          <div className="form-action">
            <Button variant="primary" disabled={busy} onClick={bulkSync}>
              {busy ? (
                <>
                  <Loader2 className="spin" size={15} />
                  {preview.length ? "加入队列中" : "扫描中"}
                </>
              ) : (
                <>
                  <Zap size={15} />
                  {preview.length
                    ? `加入队列（${selectedPreview.size}）`
                    : "预览匹配规则"}
                </>
              )}
            </Button>
          </div>
        </div>
        <div className="scope-line">
          <Check size={14} />
          范围：全部已发现安全组的入方向规则 · 保留协议、端口、优先级和描述 ·
          每条变更写入审计记录
        </div>
        {preview.length > 0 && (
          <div className="preview-panel">
            <div className="preview-head">
              <div>
                <strong>匹配规则清单</strong>
                <span>
                  默认全选，可取消不需要同步的规则。选中 {selectedPreview.size}{" "}
                  / {preview.length}
                </span>
              </div>
              <div className="inline-actions">
                <Button
                  size="sm"
                  onClick={() =>
                    setSelectedPreview(new Set(preview.map((rule) => rule.key)))
                  }
                >
                  全选
                </Button>
                <Button size="sm" onClick={() => setSelectedPreview(new Set())}>
                  清空
                </Button>
              </div>
            </div>
            <div className="preview-list">
              {preview.map((rule) => (
                <label
                  className={cn(
                    "preview-row",
                    selectedPreview.has(rule.key) && "preview-selected",
                  )}
                  key={rule.key}
                >
                  <input
                    type="checkbox"
                    checked={selectedPreview.has(rule.key)}
                    onChange={() =>
                      setSelectedPreview((current) => {
                        const next = new Set(current);
                        if (next.has(rule.key)) next.delete(rule.key);
                        else next.add(rule.key);
                        return next;
                      })
                    }
                  />
                  <span>
                    <strong>
                      {rule.security_group_name || rule.security_group_id}
                    </strong>
                    <small>
                      {rule.region} · {rule.security_group_id} · {rule.protocol}
                      :{rule.port_start}-{rule.port_end}
                    </small>
                  </span>
                  <span className="mono">{rule.cidr}</span>
                  <span className="preview-description">
                    {rule.description || "无描述"}
                  </span>
                </label>
              ))}
            </div>
          </div>
        )}
      </Card>
      <Card>
        <div className="card-head">
          <div>
            <h3>
              <Terminal size={17} />
              同步队列
            </h3>
            <span>
              火山 VPC 当前按单条规则串行处理，先新增新 IP 放行，再撤销旧
              IP，避免中途失联。
            </span>
          </div>
          <Button size="sm" onClick={onJobsRefresh}>
            <RefreshCw size={14} />
            刷新队列
          </Button>
        </div>
        <JobTable jobs={jobs || []} />
      </Card>
      <Card>
        <div className="card-head">
          <div>
            <h3>已保存的细分目标</h3>
            <span>只在需要分组、备注、停用或单独勾选规则时使用。</span>
          </div>
          <div className="inline-actions">
            <Button size="sm" onClick={importRules}>
              <Copy size={14} />
              从安全组导入
            </Button>
            <Button
              size="sm"
              onClick={() => {
                const value = oldIP.trim();
                setTargets((current) =>
                  current.map((target) => ({
                    ...target,
                    ip_match: value,
                    ip_match_mode: mode,
                  })),
                );
                notify("已应用到全部目标");
              }}
            >
              应用匹配条件
            </Button>
            <Button size="sm" variant="primary" onClick={saveTargets}>
              <Check size={14} />
              保存目标
            </Button>
          </div>
        </div>
        <div className="filters">
          <div className="search-box">
            <Search size={15} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="搜索名称、安全组或备注"
            />
          </div>
          <select
            value={group}
            onChange={(event) => setGroup(event.target.value)}
          >
            <option value="">全部安全组</option>
            {groups.map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </select>
        </div>
        <TargetTable
          targets={targets}
          filtered={filtered}
          updateTarget={updateTarget}
          setTargets={setTargets}
          notify={notify}
        />
      </Card>
    </div>
  );
}

function JobTable({ jobs }) {
  if (!jobs.length)
    return (
      <div className="empty-state">
        <Terminal size={22} />
        <span>队列为空</span>
      </div>
    );
  const statusLabel = {
    queued: "排队中",
    running: "执行中",
    succeeded: "已完成",
    completed_with_errors: "部分失败",
    failed: "失败",
  };
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>任务</th>
            <th>旧值 → 新值</th>
            <th>进度</th>
            <th>状态</th>
            <th>时间</th>
          </tr>
        </thead>
        <tbody>
          {jobs
            .slice()
            .reverse()
            .map((job) => (
              <tr key={job.id}>
                <td className="mono">{job.id}</td>
                <td className="mono">
                  {job.match} → {job.new_cidr}
                </td>
                <td>
                  {job.replaced || 0} 成功 / {job.failed || 0} 失败 /{" "}
                  {job.skipped || 0} 跳过{" "}
                  <small>共匹配 {job.matched || 0} 条</small>
                  {job.rules?.length > 0 && (
                    <details className="job-details">
                      <summary>查看涉及规则</summary>
                      {job.rules.map((rule) => (
                        <div className="job-rule" key={rule.key}>
                          <span className="mono">
                            {rule.cidr} → {rule.new_cidr}
                          </span>
                          <span>
                            {rule.group_id} · {rule.protocol}:{rule.port_start}-
                            {rule.port_end}
                          </span>
                          {rule.strategy && (
                            <small className="muted">
                              {rule.strategy === "modified"
                                ? "原地修改"
                                : "新增后撤销旧规则"}
                            </small>
                          )}
                          <Badge
                            tone={
                              rule.status === "succeeded"
                                ? "green"
                                : rule.status === "failed"
                                  ? "red"
                                  : "neutral"
                            }
                          >
                            {rule.status === "succeeded"
                              ? "成功"
                              : rule.status === "failed"
                                ? "失败"
                                : rule.status === "skipped"
                                  ? "跳过"
                                  : "排队"}
                          </Badge>
                        </div>
                      ))}
                    </details>
                  )}
                </td>
                <td>
                  <Badge
                    tone={
                      job.status === "succeeded"
                        ? "green"
                        : job.status === "failed" ||
                            job.status === "completed_with_errors"
                          ? "red"
                          : "amber"
                    }
                  >
                    {statusLabel[job.status] || job.status}
                  </Badge>
                </td>
                <td>
                  {new Date(
                    job.finished_at || job.started_at || job.queued_at,
                  ).toLocaleString()}
                </td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}

function TargetTable({ targets, filtered, updateTarget, setTargets, notify }) {
  const [selected, setSelected] = useState(new Set());
  const selectedTargets = filtered.filter((target) =>
    selected.has(target.id || target.name),
  );
  const syncSelected = async () => {
    const ids = selectedTargets.map((target) => target.id).filter(Boolean);
    if (!ids.length) return notify("请先勾选已保存且启用的目标", "error");
    try {
      await api("/api/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_ids: ids }),
      });
      notify(`已将 ${ids.length} 个目标加入同步任务`);
    } catch (error) {
      notify(error.message, "error");
    }
  };
  if (!filtered.length)
    return (
      <div className="empty-state">
        <SquareStack size={22} />
        <span>暂无已保存目标，可从安全组导入</span>
      </div>
    );
  return (
    <>
      <div className="selection-bar">
        <span>已选 {selectedTargets.length} 个目标</span>
        <div className="inline-actions">
          <Button
            size="sm"
            onClick={() =>
              setSelected(
                new Set(filtered.map((target) => target.id || target.name)),
              )
            }
          >
            全选当前
          </Button>
          <Button size="sm" onClick={() => setSelected(new Set())}>
            清空选择
          </Button>
          <Button size="sm" variant="primary" onClick={syncSelected}>
            <Zap size={14} />
            同步选中
          </Button>
        </div>
      </div>
      <div className="table-wrap">
        <table className="target-table">
          <thead>
            <tr>
              <th></th>
              <th>名称</th>
              <th>安全组 / 端口</th>
              <th>旧 IP 匹配</th>
              <th>分组</th>
              <th>备注</th>
              <th>状态</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((target) => {
              const index = targets.indexOf(target);
              return (
                <tr key={`${target.id || target.name}-${index}`}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selected.has(target.id || target.name)}
                      onChange={() =>
                        setSelected((current) => {
                          const next = new Set(current);
                          const key = target.id || target.name;
                          if (next.has(key)) next.delete(key);
                          else next.add(key);
                          return next;
                        })
                      }
                    />
                  </td>
                  <td>
                    <strong>{target.name}</strong>
                    <small>{target.region}</small>
                  </td>
                  <td>
                    <span className="mono">{target.security_group_id}</span>
                    <small>
                      {target.protocol}:{target.port_start}-{target.port_end}
                    </small>
                  </td>
                  <td>
                    <input
                      className="cell-input"
                      value={target.ip_match || ""}
                      placeholder="自动发现"
                      onChange={(event) =>
                        updateTarget(index, { ip_match: event.target.value })
                      }
                    />
                    <select
                      className="cell-select"
                      value={target.ip_match_mode || "contains"}
                      onChange={(event) =>
                        updateTarget(index, {
                          ip_match_mode: event.target.value,
                        })
                      }
                    >
                      <option value="contains">包含</option>
                      <option value="exact">精确</option>
                      <option value="cidr">网段</option>
                      <option value="prefix">前缀</option>
                    </select>
                  </td>
                  <td>
                    <input
                      className="cell-input"
                      value={target.group || ""}
                      onChange={(event) =>
                        updateTarget(index, { group: event.target.value })
                      }
                    />
                  </td>
                  <td>
                    <input
                      className="cell-input"
                      value={target.note || ""}
                      onChange={(event) =>
                        updateTarget(index, { note: event.target.value })
                      }
                    />
                  </td>
                  <td>
                    <button
                      className={cn("switch", target.enabled && "switch-on")}
                      onClick={() =>
                        updateTarget(index, { enabled: !target.enabled })
                      }
                    >
                      <span />
                    </button>
                  </td>
                  <td>
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() =>
                        setTargets((current) =>
                          current.filter((_, i) => i !== index),
                        )
                      }
                    >
                      <Trash2 size={15} />
                    </Button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Instances({ inventory, onRefresh }) {
  const [query, setQuery] = useState("");
  const rows = inventory.instances.filter((item) =>
    `${item.name} ${item.id} ${item.eip}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  return (
    <div className="view">
      <div className="view-heading">
        <div>
          <div className="eyebrow">云端资产</div>
          <h2>实例资产</h2>
          <p>四台服务器、网卡、公网地址和绑定安全组的统一视图。</p>
        </div>
        <Button onClick={onRefresh}>
          <RefreshCw size={15} />
          刷新资产
        </Button>
      </div>
      <Card>
        <div className="filters">
          <div className="search-box">
            <Search size={15} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="搜索实例名称、ID、IP"
            />
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>地域</th>
                <th>实例</th>
                <th>状态</th>
                <th>主公网 IP</th>
                <th>绑定安全组</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.id}>
                  <td>{item.region}</td>
                  <td>
                    <strong>{item.name || "未命名实例"}</strong>
                    <small className="mono">{item.id}</small>
                  </td>
                  <td>
                    <Badge
                      tone={item.status === "RUNNING" ? "green" : "neutral"}
                    >
                      {item.status}
                    </Badge>
                  </td>
                  <td className="mono">{item.eip || "-"}</td>
                  <td>{(item.security_groups || []).join("、") || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <div className="empty-state">暂无实例数据</div>}
        </div>
      </Card>
    </div>
  );
}

function Groups({ inventory, onRefresh, onOpen }) {
  const [query, setQuery] = useState("");
  const rows = inventory.groups.filter((item) =>
    `${item.name} ${item.id}`.toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <div className="view">
      <div className="view-heading">
        <div>
          <div className="eyebrow">网络边界</div>
          <h2>安全组</h2>
          <p>按地域查看每个安全组的入/出方向规则，默认全屏打开规则。</p>
        </div>
        <Button onClick={onRefresh}>
          <RefreshCw size={15} />
          刷新资产
        </Button>
      </div>
      <Card>
        <div className="filters">
          <div className="search-box">
            <Search size={15} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="搜索安全组名称或 ID"
            />
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>地域</th>
                <th>安全组</th>
                <th>规则数</th>
                <th>入方向</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.id}>
                  <td>{item.region}</td>
                  <td>
                    <strong>{item.name || "未命名安全组"}</strong>
                    <small className="mono">{item.id}</small>
                  </td>
                  <td>{item.rules?.length || 0}</td>
                  <td>
                    {item.rules?.filter((rule) => rule.direction === "ingress")
                      .length || 0}
                  </td>
                  <td>
                    <Button size="sm" onClick={() => onOpen(item)}>
                      查看规则 <ChevronRight size={14} />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <div className="empty-state">暂无安全组数据</div>}
        </div>
      </Card>
    </div>
  );
}

function RuleDrawer({ group, onClose, onChanged, notify }) {
  const [query, setQuery] = useState("");
  const [rules, setRules] = useState(group.rules || []);
  const [editing, setEditing] = useState(null);
  const visible = rules.filter((rule) =>
    `${rule.cidr} ${rule.protocol} ${rule.port_start} ${rule.description}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const remove = async (rule) => {
    if (!window.confirm("确认删除这条云端规则？")) return;
    try {
      await api("/api/rules", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          region: group.region,
          security_group_id: group.id,
          direction: rule.direction,
          cidr: rule.cidr,
          protocol: rule.protocol,
          port_start: rule.port_start,
          port_end: rule.port_end,
          priority: rule.priority,
          description: rule.description,
        }),
      });
      setRules((current) => current.filter((item) => item !== rule));
      notify("规则已删除");
      onChanged();
    } catch (error) {
      notify(error.message, "error");
    }
  };
  return (
    <Modal
      title={`${group.name || "安全组"} · ${group.id}`}
      onClose={onClose}
      wide
    >
      <div className="drawer-toolbar">
        <div className="search-box">
          <Search size={15} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="筛选 CIDR、端口、描述"
          />
        </div>
        <Button variant="primary" onClick={() => setEditing({})}>
          <Zap size={15} />
          添加规则
        </Button>
      </div>
      <div className="table-wrap rule-table">
        <table>
          <thead>
            <tr>
              <th>方向</th>
              <th>来源</th>
              <th>协议 / 端口</th>
              <th>优先级</th>
              <th>描述</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {visible.map((rule) => (
              <tr
                key={`${rule.cidr}-${rule.protocol}-${rule.port_start}-${rule.priority}`}
              >
                <td>{rule.direction}</td>
                <td className="mono">{rule.cidr}</td>
                <td>
                  {rule.protocol} /{" "}
                  {rule.port_start === -1
                    ? "ALL"
                    : `${rule.port_start}-${rule.port_end}`}
                </td>
                <td>{rule.priority}</td>
                <td>{rule.description || "-"}</td>
                <td>
                  <Button size="sm" onClick={() => setEditing(rule)}>
                    编辑
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => remove(rule)}
                  >
                    <Trash2 size={15} />
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!visible.length && <div className="empty-state">暂无匹配规则</div>}
      {editing && (
        <RuleForm
          group={group}
          rule={editing}
          onClose={() => setEditing(null)}
          onSaved={(saved) => {
            setRules((current) =>
              editing.cidr
                ? current.map((item) => (item === editing ? saved : item))
                : [...current, saved],
            );
            setEditing(null);
            onChanged();
            notify("规则已保存");
          }}
          notify={notify}
        />
      )}
    </Modal>
  );
}

function RuleForm({ group, rule, onClose, onSaved, notify }) {
  const [form, setForm] = useState({
    cidr: rule.cidr || "",
    protocol: rule.protocol || "tcp",
    port_start: rule.port_start > 0 ? rule.port_start : 22,
    port_end: rule.port_end > 0 ? rule.port_end : 22,
    priority: rule.priority || 1,
    description: rule.description || "",
  });
  const save = async (event) => {
    event.preventDefault();
    const body = {
      ...form,
      region: group.region,
      security_group_id: group.id,
      direction: "ingress",
      port_start: Number(form.port_start),
      port_end: Number(form.port_end),
      priority: Number(form.priority),
    };
    if (rule.cidr)
      Object.assign(body, {
        old_cidr: rule.cidr,
        old_protocol: rule.protocol,
        old_port_start: rule.port_start,
        old_port_end: rule.port_end,
        old_priority: rule.priority,
        old_description: rule.description,
      });
    try {
      const result = await api("/api/rules", {
        method: rule.cidr ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      onSaved(result.rule || { ...body });
    } catch (error) {
      notify(error.message, "error");
    }
  };
  return (
    <Modal
      title={rule.cidr ? "编辑安全组规则" : "添加安全组规则"}
      onClose={onClose}
    >
      <form className="form-grid" onSubmit={save}>
        <Field label="CIDR">
          <input
            required
            value={form.cidr}
            onChange={(event) => setForm({ ...form, cidr: event.target.value })}
            placeholder="1.2.3.4/32"
          />
        </Field>
        <Field label="协议">
          <select
            value={form.protocol}
            onChange={(event) =>
              setForm({ ...form, protocol: event.target.value })
            }
          >
            <option>tcp</option>
            <option>udp</option>
            <option>icmp</option>
            <option>all</option>
          </select>
        </Field>
        <Field label="起始端口">
          <input
            type="number"
            min="0"
            max="65535"
            value={form.port_start}
            onChange={(event) =>
              setForm({ ...form, port_start: event.target.value })
            }
          />
        </Field>
        <Field label="结束端口">
          <input
            type="number"
            min="0"
            max="65535"
            value={form.port_end}
            onChange={(event) =>
              setForm({ ...form, port_end: event.target.value })
            }
          />
        </Field>
        <Field label="优先级">
          <input
            type="number"
            min="1"
            max="100"
            value={form.priority}
            onChange={(event) =>
              setForm({ ...form, priority: event.target.value })
            }
          />
        </Field>
        <Field label="描述">
          <input
            maxLength="512"
            value={form.description}
            onChange={(event) =>
              setForm({ ...form, description: event.target.value })
            }
          />
        </Field>
        <div className="modal-actions">
          <Button type="button" onClick={onClose}>
            取消
          </Button>
          <Button variant="primary" type="submit">
            <Check size={15} />
            保存规则
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function Settings({ config, setConfig, onRefresh, notify }) {
  const [secrets, setSecrets] = useState({
    access_key_id: "",
    secret_access_key: "",
    password: "",
  });
  const [providers, setProviders] = useState(
    (config.ip_providers || []).join("\n"),
  );
  const save = async () => {
    try {
      await api("/api/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...secrets,
          ip_providers: providers
            .split(/\n/)
            .map((item) => item.trim())
            .filter(Boolean),
          interval: config.interval,
          schedule_times: (config.schedule_times || [])
            .join(",")
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
          web_listen: config.web_listen,
          dry_run: config.dry_run,
        }),
      });
      setSecrets({ access_key_id: "", secret_access_key: "", password: "" });
      notify("配置已安全保存，密钥不会回显");
      onRefresh();
    } catch (error) {
      notify(error.message, "error");
    }
  };
  return (
    <div className="view">
      <div className="view-heading">
        <div>
          <div className="eyebrow">系统参数</div>
          <h2>控制台设置</h2>
          <p>敏感信息仅写入本机受保护文件，页面不会回显密钥。</p>
        </div>
        <Badge tone={config.password_set ? "green" : "amber"}>
          {config.password_set ? "密码认证已启用" : "未设置登录密码"}
        </Badge>
      </div>
      <Card>
        <div className="card-head">
          <div>
            <h3>
              <KeyRound size={17} />
              火山引擎凭据
            </h3>
            <span>使用 Access Key ID + Secret Access Key，不是 API Key。</span>
          </div>
        </div>
        <div className="form-grid">
          <Field
            label="Access Key ID"
            hint={
              config.access_key_id_set ? "已保存，留空保持不变" : "尚未设置"
            }
          >
            <input
              type="password"
              autoComplete="off"
              value={secrets.access_key_id}
              onChange={(event) =>
                setSecrets({ ...secrets, access_key_id: event.target.value })
              }
            />
          </Field>
          <Field
            label="Secret Access Key"
            hint={
              config.secret_access_key_set ? "已保存，留空保持不变" : "尚未设置"
            }
          >
            <input
              type="password"
              autoComplete="off"
              value={secrets.secret_access_key}
              onChange={(event) =>
                setSecrets({
                  ...secrets,
                  secret_access_key: event.target.value,
                })
              }
            />
          </Field>
          <Field label="Web 登录密码" hint="至少 8 位，留空保持不变">
            <input
              type="password"
              autoComplete="new-password"
              value={secrets.password}
              onChange={(event) =>
                setSecrets({ ...secrets, password: event.target.value })
              }
            />
          </Field>
        </div>
      </Card>
      <Card>
        <div className="card-head">
          <div>
            <h3>
              <CloudCog size={17} />
              同步策略
            </h3>
            <span>自动任务会按频率检测公网 IP，并在变化时执行替换。</span>
          </div>
        </div>
        <div className="form-grid">
          <Field label="兜底检测间隔" hint="未设置固定时间时使用，最短 30 秒">
            <input
              value={config.interval || "2h"}
              onChange={(event) =>
                setConfig({ ...config, interval: event.target.value })
              }
            />
          </Field>
          <Field label="每日检测时间" hint="默认早晚两次：09:00,18:00，可调整">
            <input
              value={(config.schedule_times || []).join(",")}
              onChange={(event) =>
                setConfig({
                  ...config,
                  schedule_times: event.target.value
                    .split(",")
                    .map((item) => item.trim()),
                })
              }
            />
          </Field>
          <Field label="监听地址">
            <input
              value={config.web_listen || ""}
              onChange={(event) =>
                setConfig({ ...config, web_listen: event.target.value })
              }
            />
          </Field>
          <Field label="运行模式">
            <span className="check-field">
              <input
                type="checkbox"
                checked={!!config.dry_run}
                onChange={(event) =>
                  setConfig({ ...config, dry_run: event.target.checked })
                }
              />
              预演模式（不修改云端规则）
            </span>
          </Field>
          <Field label="公网 IP 查询源" hint="每行一个 HTTPS URL">
            <textarea
              rows="5"
              value={providers}
              onChange={(event) => setProviders(event.target.value)}
            />
          </Field>
        </div>
        <div className="modal-actions">
          <Button
            onClick={async () => {
              try {
                const result = await api("/api/current-ip");
                notify(`当前出口 IP：${result.cidr}`);
              } catch (error) {
                notify(error.message, "error");
              }
            }}
          >
            <Network size={15} />
            立即检测出口 IP
          </Button>
          <Button variant="primary" onClick={save}>
            <Check size={15} />
            保存配置
          </Button>
        </div>
      </Card>
    </div>
  );
}

function LoginModal({ onClose, onSuccess, onError }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    try {
      await api("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      onSuccess();
    } catch (error) {
      onError(error);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="登录控制台" onClose={onClose}>
      <form onSubmit={submit}>
        <Field label="Web 登录密码">
          <input
            autoFocus
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="请输入密码"
          />
        </Field>
        <div className="modal-actions">
          <Button type="button" onClick={onClose}>
            取消
          </Button>
          <Button variant="primary" disabled={busy} type="submit">
            {busy ? (
              <Loader2 className="spin" size={15} />
            ) : (
              <LogIn size={15} />
            )}
            登录
          </Button>
        </div>
      </form>
    </Modal>
  );
}

createRoot(document.getElementById("root")).render(<App />);
