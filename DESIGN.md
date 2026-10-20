# CodeArts 插件设计说明

## 一、参考插件与参考实现

### 1. 结构模板：`packages/workbuddy`

从 `magpie-community/plugins` 仓库中，与本任务结构最相近的模板是
**`packages/workbuddy`（`@magpie-community/opencode-workbuddy-auth`）**：

| 维度 | WorkBuddy | CodeArts | 结论 |
| --- | --- | --- | --- |
| 厂商性质 | 国内云厂商的编码订阅 | 华为云码道编码订阅 | 同类 |
| 接口协议 | OpenAI 兼容 Chat Completions | OpenAI 兼容 Chat Completions | 一致 |
| SDK | `@ai-sdk/openai-compatible` | 同 | 一致 |
| 插件形态 | provider + auth + config + usage | 同 | 一致 |
| 差异点 | 浏览器设备流登录 | **PKCE OAuth + 请求签名** | 需替换 auth 与 fetch |

### 2. 真实流程参考：`Ebony-Vinyl/dsh-our-free-model` 的 CodeArts 通道

CodeArts **不是 API Key** 登录：请求必须用临时 AK/SK/security-token 做
SDK-HMAC-SHA256 签名，凭据由 OAuth 换取。因此本插件的 auth 与签名逻辑直接对齐
该项目的 CodeArts 通道（`vendor/channel-pack/src/`）：

| 本插件实现 | 参考文件 | 作用 |
| --- | --- | --- |
| `startOAuthFlow` / `buildOAuthLoginUrl` | `login.ts` | 新式 IAM OAuth：本地回调服务器 + portal 授权 URL |
| `generatePkcePair` / `generateDpopKeyPair` / `signDpopJws` / `requestToken` | `oauth.ts` | PKCE 与 DPoP（ES256）token 交换 |
| `signRequestHuawei` | `sign.ts` | 华为 SDK-HMAC-SHA256 请求签名 |
| `fetchRemoteModels` / `parseModelInfo` / `normalizeModelId` | `models.ts` | 两个签名端点的模型列表 |
| `signedFetch`（benefit 头、Chat-Id/Session-Id/lang） | `llm-adapter.ts` | Chat Completions 请求构造 |
| `usageFromStatistics` | `codearts-credits.ts` | 积分套餐用量 |

辅助参考：`packages/cline`、`packages/zen-free`（用于确认 `loader` 返回值形态与
飞行中改写请求的写法）。

## 二、主要改造内容（相对 WorkBuddy）

1. **auth 方式：浏览器设备流 → PKCE OAuth + DPoP**
   - `methods` 改为 `[{ type: "oauth", label: "Sign in with Huawei Cloud", authorize }]`；
     `authorize()` 返回 `{ url, instructions, method: "auto", callback }`，由 magpie
     打开授权页并回调 `callback()`。
   - `authorize()` 内部：起 `127.0.0.1` 回调服务器（端口 ≥ 10000，对齐真实插件的
     端口要求）→ 生成 PKCE 对与 ES256 DPoP 密钥对 → 返回 portal 授权 URL。
   - 回调收到 `code` 后向 STS 换取临时凭据；也兼容 portal 回退到旧 ticket 流程的
     `secret` 分支。

2. **请求签名：Bearer API Key → SDK-HMAC-SHA256**
   - `loader` 不再返回 `apiKey`，而是返回 `baseURL` + 自定义 `fetch`，在 `fetch` 内
     用 `signRequestHuawei` 给请求签名。
   - benefit 模型附带**参与签名**的 `maas_type: benefit` 头；非 sign 的 `Chat-Id` /
     `Session-Id` / `lang` 头在签名后追加。
   - 网关只对 SSE 流式回答做用量归集，非流式的 200 返回 token 却不扣分（实测：
     `stream: false` 后 `usageTotalPackageCredit.package_credit_used` 为 0，
     `stream: true` 精确入账）。因此签名前把对话请求体改写为 `stream: true`，
     再把流折叠回调用方要求的 JSON；错误型流原样透传，不伪装成空回答。

3. **凭据与续期**
   - 完整凭据（AK/SK/ST/`expires_at` + `refresh_token` + `code_verifier` +
     `dpop_private_key_jwk`）以 JSON 存在账号的 `access` 字段。
   - `auth.refresh` 用 `refresh_token` 复用同一 `code_verifier` 与 DPoP 私钥续期；
     对忽略 `auth.refresh` 的宿主（OpenCode / 旧 magpie）另在 `fetch` 内做带单飞
     的临期续期兜底。

4. **端点固定为华为云 cn-north-4**
   - Chat Completions 基址 `https://snap-access.cn-north-4.myhuaweicloud.com/api/v2`。

5. **模型目录与用量**
   - 目录换成码道真实模型，并带真实上下文窗口（见 README）。
   - 实时列表来自 `opengw gateway/config`（benefit 模型）∪ `snap-access
     /v1/model/builtin`（常规模型）；对 `-VL` 视觉模型过滤。
   - **下发 id 不做去后缀改写**：`gateway/config` 公布的 4 个模型全部要带
     `maas_type: benefit` 才能调用，而带日期后缀的 id 才是后端注册的形态。
     实测：`deepseek-v4-flash-0731` 带 benefit 头 200，裸形 `deepseek-v4-flash`
     带同一头报 `InferHub.4005.200 unsupported model`，不带则报
     `InferHub.002002009.404`。两者是后端两个不同模型（计费口径相反），
     按归一化 id 去重会让免费的那个从列表里消失。日期后缀只用于展示名与
     `CONTEXT_WINDOWS` 查表。
   - `usage` 读 `statistics/plugin` 的积分口径，并读 `opengw/v1/user/tokens/balance`
     的 benefit 每日 token 额度，映射为 magpie 的 `{plan, windows}`。两条池互斥：
     免费模型只扣 `daily_tokens_used`，不动积分。
   - 免费模型在列表里带 magpie 专有字段 `free: true`（套餐免费提供、不占额度），
     与 `maas_type: benefit` 头共用 `isBenefitModel` 这一判定来源，标注与计费不分叉。
   - 路由判定只看总积分：magpie 的额度上限取自用量窗口，所以下发的窗口里只有
     「总积分」参与，其余窗口标 `aside: true`（用完不影响账号使用）；「免费额度」
     窗口再用 `models` 限定为免费模型 id，免费池耗尽不阻断付费模型。

6. **零依赖**
   - 签名与 PKCE/DPoP 全部用运行时内置 WebCrypto（`globalThis.crypto.subtle`）
     实现，不引入 `jose`；唯一的内置模块依赖是 `node:http`（本地回调服务器）。

## 三、实现步骤

1. 建包（本仓库为单包，插件直接放在仓库根目录），`package.json` 声明
   `magpie` 元数据与 `type: module`。
2. `index.mjs` 导出插件函数 `CodeArtsAuthPlugin({ client }, options)`，返回
   `{ config, provider, auth }`：
   - `config`：用 `??=` 注册 `codearts` provider 与 `CATALOG` 模型，不覆盖用户配置。
   - `provider.models`：签名拉取两个远端端点，失败回退目录。
   - `auth`：`methods` 提供 OAuth 登录，`loader` 签名请求，`refresh` 续期，
     `usage` 汇报用量。
3. `README.md` 写安装 / 登录 / 使用 / 已知限制。
4. `index.test.mjs` 覆盖签名、PKCE/DPoP、凭据往返、远端列表、loader 签名、
   续期、用量、回调服务器、流式计量与折叠、免费标注与路由口径，全程不联网
   （`node --test`，55 项）。
5. `registry-entry.json` 提供加入 `magpie` 插件市场的登记项。

## 四、目录

```
./  (仓库根 = 插件目录)
├── package.json
├── index.mjs
├── index.test.mjs
├── registry-entry.json
├── CONTRIBUTING.md          # 分支模型与同步顺序
├── README.md
└── DESIGN.md
```

分支流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，决策依据见
[main 与 develop 双分支模型](docs/wiki/decisions/codearts-branch-model.md)。

## 五、并发会话与排队（issue #1 修复）

码道按账号限制 3 个并发会话：会话在其请求结束后仍存活 60–90 秒，期间计入上限；
超出的聊天请求返回 HTTP 400 `TM.00001041`（并发会话数已达上限）。

修复前：每次请求用随机 `Chat-Id`、每个 loader 用随机 `Session-Id` 新开会话，
`signedFetch` 只处理 401/403，`TM.00001041` 原样透传 —— 任何正常调用频率都会
饱和上限后全部失败。

现在：

1. **账号级并发闸门**：同账号在途请求不超过 3 个，超出的排队等待
   （`createConcurrencyGate`，每账号一个实例）。
2. **排队重试**：`400` + `TM.00001041` 不返回给调用方，改为每 10 秒重试同一请求，
   上限 180 次（约 30 分钟）。请求体在签名前已缓冲为字节，可原样重放。
3. **状态探测**：重试前查询 `api/v1/queue/status?model=&task_id=<sessionId>`，
   返回 `queue_full` / `error` 时立即结束重试并交回上游原话；`waiting` / `working`
   或端点不可达时继续等待。非 `TM.00001041` 的 4xx 也先探测一次，命中 `waiting`
   即按排队处理（部分模型的并发限流错误码与 GLM 不同）。
4. **稳定会话 id**：登录时生成一次 `session_id` 存入凭据，`Session-Id` / `Chat-Id`
   由它派生，续期沿用旧值 —— 同一账号跨请求、跨凭据轮换保持一致（老凭据回退到
   `user_id` / `user_name` / `access_key_id`）。
5. **可取消**：等待期间 `AbortSignal` 中止立即停止重试并抛出中止原因。
6. **SSE 内嵌排队错误**：码道也会以 HTTP 200 + SSE 内嵌 `error_code`（如
   `InferHub.ModelArts.81111.429`）返回排队/限流。插件在把响应交给调用方之前读取
   流的首个事件：命中可重试的排队/限流码（`TM.00001041`、`81111`、独立的 `429`、
   `TPM`、`rate limit`）就丢弃该流并重放请求；`InferHub.4291.200`（额度用尽）等
   不可重试错误回答为 429 / 502。已读字节先回放再转发剩余流，正文保持完整。`429` 锚定为
   独立数字：参考实现曾用裸子串匹配把 `4291` 当成限流，静默重试 30 分钟。
   判定只看内容而非首个事件：上游可能先发一个只含 `role` 的空增量，再发终态错误，
   因此只含 `role` / 空增量的事件不算「已有答案」，继续读到下一个事件。
7. **故障切换（v0.1.6）**：magpie 只按非 2xx 响应切换账号，200 里内嵌的错误会被
   当作答案透传，调用方只看到 `Stream ended without finish_reason`。插件把上游
   软失败换算成对应状态码：额度用尽（SSE 内嵌 `4291`）→ 429；其他终态 SSE 错误
   → 502；凭据过期（HTTP 400 + `APIG.0602` / `security token has expired`）→ 先
   就地刷新凭据、重签、重发一次，成功即透传原回答；刷新令牌已失效
   （`STS5.1806`）→ 401 + `X-Magpie-Sign-In: expired`，magpie 标记账号并要求重新
   登录，请求转下一个账号。401/403 一律补上该响应头。
8. **视觉模型过滤**：`parseModelInfo` 按大小写不敏感匹配 `-vl`（`/-vl(-|$)/i`），
   上游以小写 `kimi-k2.6-vl` 返回时不再漏进模型列表。

对齐参考实现 `Ebony-Vinyl/dsh-our-free-model` 的 `vendor/channel-pack/src/llm-adapter.ts`
（排队端点、10 秒间隔、180 次上限、终态判定、SSE 内嵌错误处理与 `429` 边界）。
状态码映射依据 magpie 官方插件文档「失败与故障切换」：非 2xx 响应即厂商的回答，
限流或服务端错误把请求转到下一个账号或模型，401 标记账号（`X-Magpie-Sign-In`）。
