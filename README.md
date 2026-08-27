# volc-sg-sync 1.0

火山引擎 VPC 安全组公网出口 IP 自动同步工具。部署在公司长期在线电脑上，检测公司出口公网 IP，在多个地域、多个 ECS、安全组和端口规则之间安全同步白名单。

## 需求与功能

### 出口 IP 监测

- 默认每天 `09:00` 和 `18:00` 检测两次，可在 Web 设置中调整时间或改为固定间隔。
- 使用多个 HTTPS 查询源（默认五个），至少两个源返回一致结果才接受 IP。
- 保存当前 IP、上一次 IP、历史变化时间和检测结果；检测失败不会修改云端规则。

### 自动替换逻辑

1. 首次配置目标 IP 或网段，例如 `39.181.0.0`、`39.181.1.2` 或 `39.181`。
2. 出口 IP 从 `39.181.1.2` 变化为 `112.10.2.3` 时，匹配旧 IP/网段的入方向规则会被加入同步队列。
3. 同步成功后，后续自动跟踪新的出口 IP，不遗漏之前手工配置的网段规则。
4. 默认同步全部匹配规则，也可以在 Web 预览时逐条取消，或按安全组、分组、备注筛选。
5. 自动计划页面显示当前 IP、上一次 IP、未来替换值、检测计划、涉及安全组数量和具体规则数量。

### 安全组和规则管理

- 自动发现 ECS、网卡、安全组及入/出方向规则，资产快照保存到 SQLite。
- 支持四台及更多服务器、多个地域、多个安全组、同一 IP 命中多个安全组的场景。
- 可新增、编辑、删除规则；编辑通过弹窗完成，规则详情支持全屏查看。
- 支持批量选择、批量替换 IP/CIDR、分组、备注、启用/停用和模糊筛选。
- 可配置安全组下新增指定 IP/端口，也可指定哪些目标参与自动同步。

### 修改策略与队列

- 所有手动同步、自动同步和批量替换均进入单一串行队列，避免并发修改同一安全组。
- 如果云端 API 支持原地修改，则优先修改；当前火山 SDK 只提供规则描述原地修改接口。
- CIDR/IP、协议、端口或优先级变化时，火山 SDK 没有原地修改接口，使用“先新增新规则，再撤销旧规则”，避免先删除造成断连。
- 队列显示排队、执行中、成功、部分失败和失败状态，并展示每条规则的处理策略。
- 同步失败保留旧规则，等待下一次重试；每条新增、修改、撤销、跳过和失败操作均写入审计日志。

## Web 控制台

默认监听：`http://127.0.0.1:12345`。控制台包含概览、自动同步计划、同步目标、资产发现、安全组规则、任务队列、操作日志和设置页面。

可在 Web 中配置：

- 火山引擎 Access Key ID 和 Secret Access Key；
- Web 登录密码；
- IP 查询源、检测间隔、每天检测时间；
- 监听地址、预演模式（`DRY_RUN`）；
- 安全组、规则、同步目标、分组、备注和自动同步范围。

凭据不写入 YAML、SQLite、日志或 Git。建议使用仅具备目标 VPC 查询和安全组入方向修改权限的最小权限子用户。

## 配置文件

复制示例配置：

```bash
cp config.example.yaml config.yaml
```

示例规则：

```yaml
ip_providers:
  - https://api4.ipify.org
  - https://ipv4.icanhazip.com
  - https://ifconfig.me/ip

state_file: volc-sg-sync-state.json
inventory_db: volc-sg-sync.db

rules:
  - name: server-a-ssh
    region: cn-beijing
    security_group_id: sg-xxxxxxxx
    protocol: tcp
    port_start: 22
    port_end: 22
    priority: 1
    description: 公司出口动态 IP - A 服务器 SSH
```

规则名称必须唯一。工具新建的受管规则描述为 `volc-sg-sync-<name>`，历史版本的 `volc-sg-sync:<name>` 仍会兼容识别。

## 凭据设置

PowerShell：

```powershell
$env:VOLCENGINE_ACCESS_KEY_ID = "你的 Access Key ID"
$env:VOLCENGINE_SECRET_ACCESS_KEY = "你的 Secret Access Key"
```

也可以在 Web 设置中保存。不要把 AK、SK 或 API Key 提交到仓库；已经泄露的凭据应立即轮换。

## Windows 安装与运行

安装脚本默认使用当前安装包目录，不强制写入 `C:`。安装时管理员权限只弹窗授权一次，用于注册计划任务；非管理员模式会回退到当前用户登录启动。

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

安装完成后：

- 计划任务名：`VolcSgSync`；
- Web 地址：`http://127.0.0.1:12345`；
- 可通过任务计划程序手动启动、停止；
- 卸载脚本会停止任务、结束进程并清理安装文件。

构建 Windows 安装目录：

```powershell
.\packaging\windows\build.ps1 -OutputDir dist
```

脚本会构建 React 静态文件并复制到 `dist/webui/`，Go 程序通过 `-web-static-dir` 托管。

## 预演与开发

预演不会调用火山云修改接口：

```powershell
$env:DRY_RUN = "1"
.\volc-sg-sync.exe -config config.yaml -once
```

React Web 开发：

```bash
cd webui
npm install
npm run dev
```

Vite 默认监听 `127.0.0.1:5173`，并将 `/api` 代理到 Go 控制台 `127.0.0.1:12345`。

## 数据与审计

SQLite 数据库包含资产扫描、实例、安全组、完整规则、出口 IP 历史、同步目标和 `sync_events` 操作日志。云端消失的资产标记为非活动状态，不物理删除，便于追溯。

状态文件只保存每条规则上次成功同步的 CIDR，并使用原子写入和 `0600` 权限。Web 接口启用密码认证后，写操作还受到 CSRF、请求体大小和频率限制，并设置禁止嵌入和 MIME 嗅探响应头。

## 当前边界

- 当前只自动同步安全组入方向规则；
- 不修改服务器本机防火墙、雷池或其他云产品 ACL；
- 火山云没有 CIDR 原地修改 API，IP 变化必须通过新增后撤销完成；
- 真实云端操作前请先使用 `DRY_RUN=1` 验证匹配范围和规则数量。
