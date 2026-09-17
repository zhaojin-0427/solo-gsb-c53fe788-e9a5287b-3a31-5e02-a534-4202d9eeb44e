# Transparent Build Artifact Log

面向**发布流水线**的构建制品透明日志（transparency log）服务。

- **Python + FastAPI + PostgreSQL**
- 客户端提交：制品摘要、构建元数据、幂等键
- 服务端按 [JCS（RFC 8785）](https://www.rfc-editor.org/rfc/rfc8785) 规范化声明
- 按 [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) 的叶/节点哈希域分离（`0x00` / `0x01` 前缀）写入**租户独立**的 Merkle 树
- 每个树头（STH）使用 **Ed25519** 签名；密钥可轮换，旧密钥保留，旧签名永久可验
- 包含证明 / 一致性证明 / STH 签名的**验证接口完全不读取数据库**，只依据请求体即可核验

## 快速开始（Docker Compose）

```bash
docker compose up --build
```

启动后：

| 服务 | 地址 |
| --- | --- |
| API | <http://localhost:8000> |
| 交互式文档（Swagger UI） | <http://localhost:8000/docs> |
| OpenAPI | <http://localhost:8000/openapi.json> |
| PostgreSQL | 容器 `db:5432`（不对外发布端口） |

健康检查：

```bash
curl http://localhost:8000/healthz
# {"status":"ok"}
```

停止并保留数据：`docker compose stop`；连同数据卷一起清除：`docker compose down -v`。

## 配置

通过环境变量配置（见 `docker-compose.yml`，均可在 `.env` 或 shell 中覆盖）：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `POSTGRES_USER` | `translog` | 数据库用户 |
| `POSTGRES_PASSWORD` | `translog` | 数据库密码 |
| `POSTGRES_DB` | `translog` | 数据库名 |
| `API_PORT` | `8000` | 宿主机映射端口 |
| `DATABASE_URL` | 由上面三项拼装 | API 连接串（容器内） |
| `STH_EPOCH` | `0` | STH 签名中的纪元号；密钥灾难级轮换/重建日志时可递增，旧签名仍在旧纪元下有效 |

示例：`API_PORT=9000 POSTGRES_PASSWORD=s3cret docker compose up --build`。

> 私钥以 PEM 存于数据库 `tenant_keys.private_key`，适用于开发/内网部署。
> 生产环境应改为 KMS/HSM 托管，并对数据库加密静态存储。

## 数据模型与哈希规则

叶数据是**服务端构造并 JCS 规范化的声明**（不是原始请求体，因此客户端无需关心字段顺序）：

```json
{"artifact":{"algorithm":"sha256","value":"…"},"build":{…},"claim_type":"add"}
```

撤销声明为：

```json
{"artifact":{…},"build":{…},"claim_type":"revocation","reason":"…","revokes_leaf_index":3}
```

哈希：

- 叶哈希：`SHA256(0x00 || canonical_claim_utf8)`
- 节点哈希：`SHA256(0x01 || left || right)`
- 空树根：`SHA256("")`

每个叶追加后立即产生一个该树大小的已签名树头并写入 `tree_heads`，历史树头永不改写。

STH 的签名内容（Ed25519）为域分离前缀加上各字段：

```
transparent-log-v1/sth-signature
tree_id=<租户>
tree_size=<n>
timestamp=<unix 毫秒>
sha256_root_hash=<base64>
epoch=<纪元>
```

## API 一览

所有路径位于 `/tenants/{tree_id}` 之下，租户之间数据完全隔离。
错误响应统一为：`{"detail":{"code":"<机器可读码>","message":"…"}}`。

### 管理

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| PUT | `/tenants/{tree_id}` | 创建租户（幂等）并生成首个 Ed25519 密钥 |
| GET | `/tenants` | 列出租户及当前树大小/密钥数 |
| GET | `/tenants/{tree_id}/keys` | 列出该租户全部密钥（含已轮换的旧公钥） |
| POST | `/tenants/{tree_id}/keys/rotate` | 停用当前密钥并生成新密钥 |

### 追加与查询

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/tenants/{tree_id}/entries` | 追加声明（主体见下） |
| GET | `/tenants/{tree_id}/entries/{leaf_index}` | 读取叶（规范化声明 + 叶哈希） |
| GET | `/tenants/{tree_id}/sth` | 最新树头（空树返回 size=0） |
| GET | `/tenants/{tree_id}/sth/{tree_size}` | 指定历史树头 |
| GET | `/tenants/{tree_id}/proof/inclusion/{tree_size}?leaf_index=i` | 包含证明 |
| GET | `/tenants/{tree_id}/proof/consistency/{first}/{second}` | 一致性证明（`first=0` 表示空树） |

### 无状态验证（不读数据库）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/verify/inclusion` | 核验包含证明 |
| POST | `/verify/consistency` | 核验新旧树头间的一致性证明 |
| POST | `/verify/sth` | 用 PEM 公钥核验 STH 的 Ed25519 签名 |

## 使用流程示例

```bash
B=http://localhost:8000
T=tenant-acme

# 1. 创建租户（自动生成签名密钥）
curl -s -X PUT $B/tenants/$T

# 2. 追加一个制品声明
DIGEST=$(sha256sum ./release.tar.gz | cut -d' ' -f1)
curl -s -X POST $B/tenants/$T/entries \
  -H 'Content-Type: application/json' \
  -d "{
    \"idempotency_key\": \"build-42\",
    \"claim_type\": \"add\",
    \"artifact\": {\"algorithm\": \"sha256\", \"value\": \"$DIGEST\"},
    \"build\": {\"pipeline\": \"release\", \"commit\": \"9f1c…\", \"runner\": \"ci-3\"}
  }"
```

响应包含 `leaf_index`、新的 `tree_size`、规范化声明、叶哈希以及已签名 STH：

```json
{
  "tree_id": "tenant-acme",
  "leaf_index": 0,
  "tree_size": 1,
  "leaf_hash": "…base64…",
  "canonical_claim": "{\"artifact\":{\"algorithm\":\"sha256\",\"value\":\"…\"},\"build\":{…},\"claim_type\":\"add\"}",
  "replayed": false,
  "sth": {
    "tree_size": 1, "timestamp": 1789000000000, "epoch": 0,
    "root_hash": "…", "key_id": 1,
    "signature": "…base64…",
    "public_key": "-----BEGIN PUBLIC KEY-----\n…"
  }
}
```

### 幂等语义

- 同 `idempotency_key` + **同内容**：返回**原始结果**（原叶序号、原 STH），`replayed=true`，树不增长。
- 同键 + **不同内容**（规范化声明不同）：返回 `409 idempotency_conflict`。
- 并发追加在数据库中以「租户行级锁 + 事务」串行化，叶序号严格连续、唯一、不覆盖（见下方并发测试）。

### 取包含证明并无状态验证

```bash
curl -s "$B/tenants/$T/proof/inclusion/1?leaf_index=0"
# {"leaf_index":0,"tree_size":1,"leaf_hash":"…","root_hash":"…","hashes":[]}

curl -s -X POST $B/verify/inclusion -H 'Content-Type: application/json' -d '{
  "leaf_index": 0, "tree_size": 1,
  "leaf_hash": "…", "root_hash": "…", "hashes": []
}'
# {"valid": true}
```

### 一致性证明（任意两个树头）

```bash
curl -s "$B/tenants/$T/proof/consistency/2/5"
# POST /verify/consistency 用同样字段回传 -> {"valid": true}
```

### 撤销（只追加，不改写历史）

```bash
curl -s -X POST $B/tenants/$T/entries \
  -H 'Content-Type: application/json' \
  -d '{
    "idempotency_key": "revoke-7",
    "claim_type": "revocation",
    "artifact": {"algorithm": "sha256", "value": "<被撤销制品摘要>"},
    "build": {"advisory": "SEC-2026-04"},
    "revokes_leaf_index": 3,
    "reason": "signature verification failure"
  }'
```

撤销是一条新的叶（叶序号继续递增），被撤销的原叶与所有历史树头保持不变。

### 密钥轮换

```bash
curl -s -X POST $B/tenants/$T/keys/rotate
# 之后新 STH 用新 key_id 签名；GET .../keys 可取得旧公钥，
# /verify/sth 对新旧签名分别用对应公钥均能验证。
```

## 错误码

| HTTP | code | 触发条件 |
| --- | --- | --- |
| 404 | `tenant_not_found` | 租户不存在 |
| 404 | `entry_not_found` | 叶序号不存在 |
| 404 | `tree_head_not_found` | 该树大小没有对应树头 |
| 400 | `leaf_not_incorporated` | 叶存在但尚未纳入所请求的树头 |
| 400 | `tree_size_unavailable` | 请求的树大小超过当前树 |
| 409 | `idempotency_conflict` | 幂等键已被不同内容占用 |
| 422 | `invalid_tenant` / `invalid_claim` / `revoked_leaf_not_found` / `invalid_hash` 等 | 参数校验失败 |
| 422 | FastAPI 校验错误 | 摘要长度不符、缺少撤销字段、树大小倒挂等 |

## 并发正确性

追加事务先 `SELECT … FROM tenants WHERE id=%s FOR UPDATE` 获取租户行锁，
再在同一事务中以 `max(leaf_index)+1` 分配新序号并写入叶与树头：

- 同一租户的所有追加串行化 → 叶序号连续、不覆盖、不丢失；
- 不同租户互不阻塞；
- 冲突时事务回滚并返回 `409`，不会留下半个写入。

## 本地开发与测试

```bash
pip install -r requirements-dev.txt

# 纯逻辑单元测试（JCS、Merkle 包含/一致性证明、负向用例），无需数据库
pytest tests/test_jcs.py tests/test_merkle.py

# 端到端：先 docker compose up，再执行（默认访问 localhost:8000）
BASE_URL=http://localhost:8000 pytest tests/test_api.py
```

`tests/test_api.py` 覆盖：追加与读取、幂等命中/冲突、25 路并发连续序号、
包含与一致性证明的无状态验证、撤销只追加、密钥轮换后旧签名仍有效、
以及全部不存在/越界/未纳入错误路径。

## 目录结构

```
app/
  main.py      FastAPI 路由、事务编排、无状态验证端点
  jcs.py       RFC 8785 JSON 规范化（UTF-16 排序、ECMAScript 数字）
  merkle.py    RFC 6962 叶/节点哈希、包含证明、一致性证明及验证
  crypto.py    Ed25519 密钥生成与 STH 签名/验证
  db.py        PostgreSQL schema 与数据访问（行锁、幂等、树头）
  schemas.py   Pydantic 请求/响应模型
tests/         单元测试与端到端测试
docker-compose.yml / Dockerfile
```
