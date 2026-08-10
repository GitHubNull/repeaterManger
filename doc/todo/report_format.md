# Privilege Escalation Test Report

> Generated: 2026-08-10 | Repeater Manager v2.41.0

## Summary

| Metric | Count |
|--------|-------|
| Total Tests | 2 |
| Escalated (&#9888;) | 0 |
| Safe (&#10004;) | 2 |
| Errors (&#10007;) | 0 |
| Baseline | 3 |
| Unique Endpoints | 3 |

## Test Info

| Item | Value |
|------|-------|
| Report Title | 越权测试报告（可自定义标题/副标题，v2.35.0+） |
| Test Target | 目标系统名称/地址 |
| Test Entry | 测试入口 URL 或功能模块 |
| Time Range | 测试时间段（DateTimeRangePickerDialog 选择） |
| Personnel | 测试执行人/团队 |

## User Info

| Session | Role | Username | Anonymous | Screenshots |
|---------|------|----------|-----------|-------------|
| user1 | 管理员 | admin | false | 登录成功页.png、个人中心.png |
| user2 | 普通用户 | user01 | false | （无） |
| guest | 访客 | （空） | true | （无） |

> 权限证明截图以 Base64 内嵌于报告；HTML 报告中支持图片灯箱轮播查看。

## Interface Classification

| Category | Interfaces |
|----------|------------|
| Escalated (&#9888;) | `GET /api/v1/users/{id}/detail HTTP/1.1`（命中规则组：状态码+敏感关键词） |
| Safe (&#10004;) | `GET /api/v1/orders/list HTTP/1.1` |
| Error (&#10007;) | `POST /api/v1/admin/config HTTP/1.1`（基准响应无效） |

## Session Breakdown

| Session | Escalated | Safe | Errors | Total |
|---------|-----------|------|--------|-------|
| user1 | 0 | 2 | 0 | 2 |
| guest | 1 | 1 | 0 | 2 |

## Findings by Endpoint

### api_01
#### orin http data
##### request
##### response

#### user_01 http data
##### request
##### response

#### user_... http data
##### request
##### response

#### user_N http data
##### request
##### response

> 每条用户会话记录包含：原始/替换请求与响应详情、命中规则组名称（matchedRuleName）、相似度得分、HTTP 状态码/响应长度/响应时间。

### api_...
#### orin http data
##### request
##### response

#### user_... http data
##### request
##### response

#### user_N http data
##### request
##### response


### api_Y
#### orin http data
##### request
##### response

#### user_... http data
##### request
##### response

#### user_N http data
##### request
##### response

## Reproduction Commands

### api_01 (user_01)

```bash
# cURL
curl -X GET 'https://target/api/v1/users/1/detail' \
  -H 'Authorization: Bearer <user1-token>'

# Postman
# 使用 PostmanSnippetBuilder 生成的代码片段，可直接导入 Postman 复现
```

> 报告格式：PDF（内嵌中文字体）/ HTML（灯箱轮播 + 越权测试用例参考 test_cases.html：TC-UA/TC-VP/TC-HP 共 9 用例）/ Markdown（本模板）/ ERMR（AES-256-CBC + HMAC-SHA256 加密容器）。
