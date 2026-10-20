---
title: CodeArts 非流式请求不计费与免费额度口径
type: query
tags: [CodeArts, 计费, 积分, 免费额度, SSE, 流式]
created: 2026-10-16
updated: 2026-10-16
sources: []
status: active
---

# CodeArts 非流式请求不计费与免费额度口径

## 问题

用户提问：判断额度用总积分（基础积分含在总积分内），为什么免费模型没消耗额度？
排查中发现更严重的问题：插件发出的**全部**请求都不产生积分消耗。

## 实测证据（账号：体验版 `codearts.agent.individual.trial`）

`statistics/plugin` 在实验全程返回 `package_credit_amount=6500`、`package_credit_remain=6500`、
`package_credit_used=0`，`usageTokenChatMessages.usage_token_num` 也不增长，而每次
Chat Completions 都返回 HTTP 200 与真实 token 用量。

单变量对照（其余条件与请求体完全相同）：

| 请求方式 | 本次 tokens | `package_credit_used` | `usage_token_num` |
| --- | --- | --- | --- |
| `stream: false` | 690 / 520 / 432 | 不变 | 不变 |
| `stream: true` | 561 | 8.95 → 9.26 | +561，与本次一致 |

结论：网关只对 SSE 流式回答做用量归集与计费。插件此前所有请求非流式，因此完全脱离计费。

排除了的请求头假设：按官方客户端日志（`header-debug] full headers`）补齐
`x-ot-trace-id`、`x-ot-session-id`、`x-ot-function`、`model-id`、`plugin-name` 等整套头后，
`package_credit_used` 仍为 0。计费与这些头无关。

## 根因

1. 计费口径挂在流式响应上：CodeArts 在流结束时才把 token 用量归集到账号额度池。
2. 免费模型（`maas_type: benefit`）本就不进积分池，而是扣独立的每日 token 免费额度：
   `opengw.developer.huaweicloud.com/api/v1/user/tokens/balance`
   （`daily_token_limit=10000000`；实测请求 68 / 86 tokens 后 `daily_tokens_used` 同步增加，
   同时 `package_credit_used` 保持 0）。
   所以"免费模型没消耗额度"是后端的正常计费隔离；插件此前没读这个池，才让它看起来像异常。

## 解法

见 [CodeArts provider 插件](../entities/codearts-plugin.md)：

- `signedFetch` 内的流式计量判定：签名前把带 `model` + `messages` 且 `stream !== true` 的对话请求体
  改写为 `stream: true`。改写必须在签名之前，请求体参与 `SDK-HMAC-SHA256` 的 payload hash。
- `parseSseEvents` + `completionFromChunks`：把 SSE 折叠回 OpenAI 非流式 JSON
  （`content`、`reasoning_content`、按 `index` 拼接的 `tool_calls`、`finish_reason`、`usage`），
  宿主无感知。
- `foldStreamToCompletion`：流内没有任何 `choices` 时判定为上游错误（额度、路由），
  原样透传响应体，不折叠成空回答。宿主自己请求 `stream: true` 时完全不改。
- `benefitWindow` + `usage`：用量面板增加「免费额度」窗口（单位 tokens），
  显示 benefit 池的每日已用/上限。

## 验证

- `node --test`：52 项通过（加入免费标注与路由口径的用例后为 55 项）。
- 真实联网（走插件 `loader`）：`stream: false` 请求 432 tokens → `Δusage_token_num=432`、
  `Δcredits=0.23`；`stream=true` 请求 463 tokens → `Δ=463`、`Δcredits=0.25`。
- benefit 模型走折叠链路后：`Δ免费额度=68`/`86`，`Δ积分=0.00`，两条池保持隔离。
- `glm-5.3-flash` 折叠后 `content=""` 属正常：该模型把 `max_tokens` 预算全部用于推理，
  `reasoning_content` 913 字符完整保留，原始流 delta 计数为 `content:67 / reasoning_content:66`。

## 后续需求：免费标注与路由口径（同日）

用户提出「模型列表中免费的模型显示免费，路由判断按照总积分判断」。实现与依据见
[用量窗口只让总积分参与路由](../decisions/codearts-usage-window-routing.md)：免费模型
带 magpie 模型字段 `free: true`，四个积分口径里只有「总积分」窗口参与路由上限，
其余窗口（含免费额度）标 `aside: true`。

## 涉及模块

> 免费标注与路由口径见 [CodeArts 用量窗口只让总积分参与路由](../decisions/codearts-usage-window-routing.md)。

- `index.mjs`：`signedFetch`、`parseSseEvents`、`completionFromChunks`、
  `foldStreamToCompletion`、`benefitWindow`、`usageFromStatistics`、`auth.usage`
- `index.test.mjs`：流式计量与折叠的 7 个用例
- `README.md` / `DESIGN.md`：计费口径与流式计量说明

## 复发预防

- 任何新增的对话请求路径都必须经过 `signedFetch` 的流式改写，不得绕过；
  否则该路径的消耗不计费。
- 判定"请求是否计费"要用 `usage_token_num` 增量与本次返回 tokens 做等式核对，
  不能只看 HTTP 200 或 `usage` 字段。
- `InferHub.4291.200`（额度耗尽）仍是不可重试终态，见
  [会话排队重试与并发闸门](../decisions/codearts-session-queue-retry.md)。
