# 内网 HTTPS 证书链选配器

内网 HTTPS 代理的证书链有**部署字节上限**。值班员为一张已签发的叶子证书，从
至多 8 张候选中间证书里选配中间 CA（允许零张），从叶子开始按签发关系排成一条
PEM 链；至多 4 批终端各持自己的根证书包与字节上限，在同一核验时刻按服务域名
核验这条链。工具在**所有批次都验证通过**的链里取叶子 + 中间证书的 **DER
总字节数最小**的一条：

- 装得下 → 显示字节数与可一键复制的 PEM；
- 最小链仍超限 → 报出至少需要多少字节（仍给出该最小链 PEM）；
- 没有任何链能同时通过全部批次 → 提示无解，并列出每批终端的 openssl 失败原因。

## 1. 模型与规则

| 输入 | 约束 |
| --- | --- |
| 服务域名 | 1 个，参与 SAN/CN 主机名校验 |
| 叶子证书 | 1 张 PEM，原样保留，不参与选配 |
| 候选中间证书 | 0~8 张，每槽 1 张 PEM；按 DER 去重；允许同一中间 CA（同主题同公钥）由不同上级签发的多张证书 |
| 终端批次 | 1~4 批，每批一个根证书包 PEM + 一个正整数部署字节上限 |

- **签发关系**：候选证书的主题 Name（DER）等于当前证书的颁发者 Name（DER）
  才能接到链尾；同一主题不允许在链中重复（RFC 5280 合法链无重复主题，也借此
  切断交叉签发环）。
- **候选链枚举**：从叶子做 DFS，每个路径前缀都是候选链——包括零张中间证书的
  “仅叶子”链，因为信任锚可能在链的任意深度出现；不可达的候选（主题与任何
  颁发者都不匹配）自然不会出现在枚举结果里。
- **核验**：每条候选链调用本机
  `openssl verify -no-CAfile -CAfile <根包> -untrusted <中间证书> -verify_hostname <域名>`，
  信任锚仅来自该批根包（不加载系统默认 CA），同时完成签名/有效期/基本约束与
  主机名校验；核验时刻为当前系统时间，全部批次同一时刻。
- **选优**：候选链按 DER 总字节升序排列，核验结果按“链 × 根包内容”缓存；
  第一条全部批次通过的链即全局最小可行链，再对照各批字节上限判定
  `fit / too_large`；没有全过链则判 `infeasible` 并给每批失败原因统计。
- 枚举路径设有 10000 条安全上限（8 张候选的真实拓扑远达不到），防御恶意构造。

## 2. 目录结构

```
app/
  certutil.py     # PEM 解析、DER 字节/指纹、openssl verify 封装
  planner.py      # 签发关系图、候选链枚举、核验缓存、最小链选优与诊断
  app.py          # Flask 路由（/、/api/select、/api/sample、/api/summaries）
  templates/      # 单页界面（原生 JS，无前端构建）
  static/         # 样式
scripts/
  generate_samples.py  # 生成含交叉签发/多级链/过期候选/干扰项的演示 PKI
samples/          # 已生成的样例（根/候选中间/叶子/根包/sample.json）
tests/            # pytest：求解器 14 项 + API 8 项
Dockerfile, docker-compose.yml
```

## 3. 启动方式

### Docker Compose（推荐）

```bash
docker compose up --build
# 浏览器打开 http://localhost:8000
```

镜像内安装 openssl（核验执行器），gunicorn 启动，含 `/api/sample` 健康检查。

### 本地直接运行

```bash
pip install -r requirements.txt
python scripts/generate_samples.py samples   # 已随仓库生成，可重复执行
flask --app app.app run --host 0.0.0.0 --port 8000
```

## 4. 网页试跑流程

1. 打开页面后样例自动载入（6 张候选 × 3 批终端）；每个 PEM 输入框失焦后显示
   解析概要（主题 CN、颁发者、DER 字节、有效期；根包显示证书数与合计字节）。
2. 点“选配最小证书链”，默认样例得到 **fit**：最小链 1954 字节
   （叶子 998 + root-a 直签 tier2 956），3 批全部通过，附可复制 PEM 与逐批核验表。
3. 试其它场景：
   - 把任一批的“部署字节上限”改成 1024 → **too_large**，提示该批至少需要
     1954 字节（超出多少），仍展示最小链 PEM；
   - 把三批根包换成互不相交的单根包（A、B、A）→ **infeasible**，列出每批
     在全部候选链上的通过数与 openssl 失败原因；
   - 把全部批次根包换成 `samples/bundles/root-b-bundle.pem` → 选中交叉签发
     长链（叶子 + tier2 + tier1 的 B 根签发版本，2 张中间，2930 字节）；
   - 域名改成证书 SAN 之外的名字 → 无解，原因 `hostname mismatch`（附实际 SAN）。

### 样例 PKI 拓扑

```
root-a ─┬─ tier1 CA（A 签发，同主题同公钥的还有 B 根签发版本与一个过期版本）
        ├─ tier2 CA（root-a 直签，短链分支）
        └─ tier1(A) ─ tier2 CA ─ leaf(demo.service.internal)
root-b ── tier1 CA（B 签发，交叉签发分支）
（另有一张与任何签发关系都不匹配的干扰候选，枚举时自动忽略）
```

## 5. 实测结果

环境：Python 3.11 + OpenSSL 3.0.22，`pytest tests/` 共 **22 项全部通过**
（求解器 14 项 + Flask API 8 项），覆盖：

- 枚举包含仅叶子链、按 DER 字节升序、指纹去重、环（自引用候选）不死循环；
- 默认样例选出最小共用链，且任何更小的候选链都至少在一批核验失败（最小性）；
- 字节超限返回 `too_large` 并给出所需字节与溢出量；
- 根包互不相交返回 `infeasible`，每批诊断含 openssl 原因与出现次数；
- 仅信任 root-b 时自动走交叉签发的 tier1-b 长链；
- 过期候选被 openssl 以 `certificate has expired` 淘汰；零候选只枚举仅叶子链；
- 域名不匹配返回 `hostname mismatch` 并附叶子 SAN；重复候选按 DER 去重；
- 空域名、非法 PEM、叶子栏多证书、非正上限、空批次、候选超 8 张均返回 400。

HTTP 端到端冒烟（真实 Flask 服务）四种返回：

| 场景 | status | 关键输出 |
| --- | --- | --- |
| 默认样例 | `fit` | 1954 字节，2 张证书 PEM，3/3 批通过且不超限 |
| 批次3 上限改 1024 | `too_large` | `required_bytes=1954`，溢出 930 字节，仍返回 PEM |
| 三批根包 A/B/A 互不相交 | `infeasible` | 每批通过链数与 `unable to get local issuer certificate` 统计 |
| 空表单 | 400 | `至少需要 1 批终端` |

另用 openssl CLI 对返回 PEM 独立复核（拆出 leaf/untrusted 直接
`openssl verify`），结果 OK，DER 合计与链上证书字节一致。

## 6. 约束与余项

- 本沙箱无 docker CLI，**Docker Compose 未在本机构建验证**；Dockerfile 依据
  python:3.11-slim 常规行为编写（显式 apt 安装 openssl、gunicorn 启动），
  请在有 Docker 的环境执行 `docker compose up --build` 复核。
- 核验通过每次请求的临时文件调用 openssl 子进程完成；候选上限 8、批次上限 4，
  枚举路径有 10000 条硬上限，核验按“链指纹 × 根包内容”缓存，实测秒级返回，
  未做高并发压测。
- 工具只做离线选配与核验，不连接任何真实服务、不保存录入内容（数据仅存在于
  浏览器与单次请求内存中）。
- 样例私钥仅在生成脚本内存中使用，不落盘私钥文件；样例证书禁止用于真实环境。
- 链文件约定：叶子在前、中间 CA 依次在后；根证书不放进链，只放终端根包。
