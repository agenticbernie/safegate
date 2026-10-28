# Safegate — PRD, Spec & Technical Architecture

> **Khuyến nghị:** Ship CLI phân tích tĩnh trước, đóng gói thành Docker GitHub Action chạy trên runner của khách hàng. Không xây SaaS control plane trong MVP; đó là cách nhanh nhất để chứng minh có người trả tiền mà không phá privacy.

## Phạm vi và nguyên tắc

Safegate là Postgres Migration Safety Gate. Công cụ phân tích migration SQL trước khi merge, phát hiện các thay đổi có nguy cơ gây lock, table rewrite, mất dữ liệu hoặc migration failure.

- Chạy mặc định local hoặc trên self-hosted GitHub runner.
- Không gửi SQL, schema hoặc data ra server ngoài theo mặc định.
- Không hứa “migration an toàn tuyệt đối”. Kết quả phụ thuộc PostgreSQL version, kích thước bảng, workload và lock hiện tại.
- Parser confidence thấp hoặc statement không hiểu được không được gắn `SAFE`; chuyển thành `REVIEW` hoặc `UNKNOWN`.

---

# Phần 1 — PRD: Bản năng sinh tồn

## 1. ICP, người dùng và người trả tiền

| Vai trò | Cụ thể | Giá trị nhận được |
|---|---|---|
| Người cài | Backend/platform engineer hoặc tech lead; team 5–30 dev; dùng SQL files, Alembic hoặc migration tool trên GitHub Actions | PR bị chặn trước khi migration gây lock, rewrite hoặc mất dữ liệu |
| Người dùng hàng ngày | Developer mở PR và reviewer database | Nhận badge `🟢 SAFE` / `🟡 REVIEW` / `🔴 BLOCK` cùng lý do và cách sửa |
| Người quẹt thẻ | CTO, Head of Engineering, VP Engineering hoặc engineering manager của startup/scale-up có PostgreSQL production | Giảm xác suất incident và chuẩn hoá database review mà không cần gửi schema ra ngoài |

## 2. Pain point — incident mẫu

Developer merge migration tạo index thường trên bảng lớn trong giờ traffic cao. PostgreSQL phải giữ lock khiến ghi bị chặn; connection pool đầy, API latency tăng rồi timeout. Rollback ứng dụng không giải phóng ngay các truy vấn đang xếp hàng, nên đội vận hành phải kill session, rollback migration hoặc restore.

Đây là kịch bản minh hoạ. Thời lượng và mức độ ảnh hưởng phải đo bằng dữ liệu của khách hàng.

**Khoảnh khắc Safegate phải thắng:** comment trên PR nói rõ `CREATE INDEX` thiếu `CONCURRENTLY`, status `🔴 BLOCK`, và đưa patch gần đúng để developer sửa trước khi merge.

## 3. Pricing model đề xuất

| Tier | Giá đề xuất | Giới hạn / tính năng | Buyer |
|---|---:|---|---|
| Free | `$0` | CLI local; public repo; 1 policy mặc định; không telemetry bắt buộc | Developer thử nghiệm |
| Team | `$49 / repo / tháng` | Private repo; GitHub PR comment; policy config; runtime metadata read-only; email support | Tech lead / Head of Engineering |
| Enterprise | `Từ $499 / tháng` hoặc báo giá | Self-hosted package; nhiều org/repo; SSO/SAML nếu cần; audit log; policy pack; SLA/support | CTO / platform team |

**Không build billing trong 4 tuần đầu.** Dùng landing page + checkout/payment link hoặc invoice thủ công để kiểm chứng 3 khách hàng Team đầu tiên.

## 4. Success metrics trong 30 ngày

### Ngưỡng Build tiếp

- Ít nhất **3 team trả tiền**.
- Ít nhất **10 repo active hàng tuần**.
- Ít nhất **5 qualified design partners**.
- False-positive nghiêm trọng dưới **10%** trên các finding đã được reviewer đánh giá.

### Ngưỡng Pivot

- Có ít nhất 10 repo active nhưng dưới 3 team trả tiền.
- Khi đó kiểm chứng lại packaging, pricing hoặc định vị: từ “safety gate” sang migration review/reporting.

### Ngưỡng Kill

- Dưới 5 repo active và chỉ 0–1 team trả tiền sau ít nhất 20 cuộc tiếp cận ICP có chất lượng.

---

# Phần 2 — Spec: Luật đi săn, MVP 4 tuần

## 1. Mười rule PostgreSQL trong MVP

| ID | Phát hiện | Mặc định | Khuyến nghị |
|---|---|---|---|
| SG-001 | `CREATE INDEX` / `CREATE UNIQUE INDEX` không có `CONCURRENTLY` | BLOCK | Dùng `CREATE INDEX CONCURRENTLY`; kiểm tra transaction boundary |
| SG-002 | `DROP INDEX` không có `CONCURRENTLY` | BLOCK | Dùng `DROP INDEX CONCURRENTLY` nếu phù hợp; kiểm tra dependency |
| SG-003 | `ADD PRIMARY KEY` / `UNIQUE` tạo index ngầm trong `ALTER TABLE` | BLOCK | Tạo unique index concurrently trước, sau đó attach constraint nếu workflow hỗ trợ |
| SG-004 | `ADD COLUMN` có `DEFAULT` không phải constant/immutable hoặc version-sensitive | REVIEW/BLOCK | Tách add column, backfill theo batch, set default sau; xác minh theo PG version |
| SG-005 | `SET NOT NULL` hoặc thêm `NOT NULL` trên bảng đã có dữ liệu | REVIEW | Backfill, thêm `CHECK NOT VALID` rồi `VALIDATE`; chỉ set `NOT NULL` sau khi có bằng chứng |
| SG-006 | `ALTER COLUMN TYPE` có nguy cơ rewrite bảng | REVIEW/BLOCK | Tạo cột mới, backfill batch, dual-write, cutover; allowlist conversion an toàn sau research |
| SG-007 | `ADD FOREIGN KEY` / `CHECK` không dùng `NOT VALID` rồi validate riêng | REVIEW | `ADD ... NOT VALID`; `VALIDATE CONSTRAINT` ở bước kiểm soát tải |
| SG-008 | `VACUUM FULL`, `CLUSTER`, `REINDEX` không concurrent hoặc rewrite nặng | BLOCK/REVIEW | Chạy ngoài migration window; dùng biến thể concurrent khi PostgreSQL hỗ trợ |
| SG-009 | `DROP TABLE/COLUMN`, `TRUNCATE`, `DELETE/UPDATE` không có `WHERE` hoặc `WHERE` luôn đúng | BLOCK | Có backup/rollback plan; giới hạn phạm vi và yêu cầu approval |
| SG-010 | `CREATE INDEX CONCURRENTLY` nằm trong transaction block | BLOCK | Tách statement ra migration không bao transaction |

### Nguyên tắc policy

- Mỗi finding phải có rule ID, severity, evidence, source location và recommendation.
- Có `confidence` từ 0 đến 1.
- Case thiếu context chuyển thành `REVIEW`, không tự động `SAFE`.
- Rule configuration phải cho phép allowlist theo PostgreSQL version và object.

## 2. Tuần 1 — Core CLI

### Input

- Một hoặc nhiều file `.sql`.
- Glob migration, ví dụ `db/migrations/**/*.sql`.
- Tuỳ chọn PostgreSQL version.
- File policy `.safegate.toml`.

### Output

- Exit code.
- JSON report gồm findings, line/column, rule ID, severity, evidence, recommendation và status `SAFE` / `REVIEW` / `BLOCK`.

### Definition of Done

- Chạy được:

```bash
safegate scan db/migrations --format json
```

- Không có network call.
- Exit code ổn định:
  - `0`: SAFE.
  - `1`: REVIEW hoặc BLOCK theo policy.
  - `2`: tool/parser error.
- Parse được các statement PostgreSQL trong test fixture.
- Parser failure không trả về SAFE.

### JSON report mẫu

```json
{
  "schema_version": "1.0",
  "status": "BLOCK",
  "summary": {
    "safe": 0,
    "review": 1,
    "block": 1
  },
  "findings": [
    {
      "rule_id": "SG-001",
      "severity": "high",
      "file": "db/001_add_idx.sql",
      "line": 4,
      "message": "CREATE INDEX may block writes; CONCURRENTLY is missing.",
      "recommendation": "Use CREATE INDEX CONCURRENTLY outside a transaction block.",
      "confidence": 0.98
    }
  ]
}
```

## 3. Tuần 2 — GitHub Action Integration

### Input

- Pull request event.
- Repository đã checkout.
- `GITHUB_TOKEN`.
- Glob migrations và policy.

### Output

- Một PR comment idempotent.
- Badge `🟢 SAFE` / `🟡 REVIEW` / `🔴 BLOCK`.
- Annotation theo file nếu làm được.
- Check run pass/fail.

### Definition of Done

- Chạy được trên GitHub-hosted hoặc self-hosted runner.
- Comment không nhân bản khi re-run.
- SQL/schema không gửi ra ngoài.
- `fail-on: block` hoạt động.
- Token chỉ có quyền comment/check tối thiểu.

### Workflow mẫu

```yaml
name: Safegate

on: [pull_request]

jobs:
  migration-safety:
    runs-on: [self-hosted, linux]
    permissions:
      contents: read
      pull-requests: write
      checks: write
    steps:
      - uses: actions/checkout@v4

      - uses: safegate/action@v0.1
        with:
          files: db/migrations/**/*.sql
          fail-on: block
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## 4. Tuần 3 — Runtime Context

### Input

- Static report.
- DSN read-only do khách hàng tự cấu hình.
- Runtime check mặc định tắt.

### Output

- Table size.
- Estimated row count.
- Relation size.
- Best-effort lock snapshot.
- Nếu DB unavailable hoặc thiếu quyền, giữ kết quả static và chuyển runtime context thành `UNKNOWN`.

### Definition of Done

- Xử lý connection timeout, SSL và privilege error.
- Query allowlist chỉ đọc catalog/statistics.
- Không đọc row data.
- Secret không xuất vào log.
- Có documented limitation về visibility của `pg_locks` và `pg_stat_activity`.
- Có statement timeout và connection timeout.

### AI trong MVP

Chưa đưa hosted AI vào MVP. Dùng template fix deterministic.

Nếu thử AI:

- Chỉ opt-in.
- Chạy local/self-hosted hoặc gửi snippet đã redact.
- Không gửi schema/data mặc định.
- Cần research thêm về threat model, retention và prompt injection.

## 5. Tuần 4 — Testing & Polish

### Input

- Tối thiểu 20 fixture SQL.
- Nhiều PostgreSQL version/policy fixture.
- Docker build.
- GitHub Action test repository.

### Output

- Package CLI.
- Docker image reproducible.
- JSON schema versioned.
- README quickstart.
- Changelog.
- Benchmark nhỏ.

### Definition of Done

- Có ít nhất **24 test cases**.
- Test parser failure.
- Snapshot JSON ổn định.
- Docker chạy được không cần network lúc scan.
- Action pass/fail đúng.
- Docs có cảnh báo version-dependent behavior.

### Phân bổ test tối thiểu

| Nhóm test | Số lượng | Ví dụ |
|---|---:|---|
| Index / constraint | 6 | `CREATE INDEX`, unique, drop index, PK, FK `NOT VALID`, `CONCURRENTLY` trong transaction |
| ALTER / rewrite | 5 | `ADD COLUMN DEFAULT`, `SET NOT NULL`, `ALTER TYPE`, `CLUSTER`, `REINDEX` |
| Destructive DDL/DML | 4 | `DROP COLUMN`, `DROP TABLE`, `TRUNCATE`, `UPDATE/DELETE` không `WHERE` |
| Parser / SQL edge | 4 | comments, quoted identifiers, multiple statements, unsupported syntax |
| Output / Action | 5 | status mapping, exit code, idempotent comment, missing token, DB timeout |

---

# Phần 3 — Technical Architecture: Vũ khí

## 1. Tech stack

| Lớp | Lựa chọn | Lý do / giới hạn |
|---|---|---|
| CLI | Python 3.12 + Typer | UX rõ, subcommands `scan`, `doctor`, `serve`; dễ test |
| Parser | `pglast` | PostgreSQL-specific AST; phù hợp hơn parser SQL generic. Cần pin version và test theo PG versions hỗ trợ |
| Model/schema | Pydantic v2 + JSON Schema | Report contract rõ, dễ consume bởi Action/UI |
| Runtime DB | psycopg 3 | Read-only catalog/statistics; không đọc business rows |
| Local API | FastAPI + Uvicorn | Tuỳ chọn cho self-hosted service; không cần để chạy CLI/Action MVP |
| GitHub | Docker Action + GitHub REST API | Chạy ngay trên workspace runner; comment idempotent theo marker |
| Config | `tomllib` | Không cần thêm YAML dependency cho policy core |
| Quality | pytest, pytest-cov, Ruff, mypy | Regression, lint, format và type check nhanh |
| Packaging | uv/pip build + `python:3.12-slim` | Lock dependency và image nhỏ; production nên pin image digest |

## 2. Repository structure

```text
safegate/
├── pyproject.toml
├── uv.lock
├── README.md
├── LICENSE
├── Dockerfile
├── action.yml
├── .safegate.toml.example
├── src/
│   └── safegate/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── exit_codes.py
│       ├── report.py
│       ├── parser/
│       │   ├── postgres.py
│       │   └── locations.py
│       ├── rules/
│       │   ├── base.py
│       │   ├── index.py
│       │   ├── alter.py
│       │   ├── constraints.py
│       │   ├── destructive.py
│       │   └── registry.py
│       ├── runtime/
│       │   ├── inspector.py
│       │   ├── queries.py
│       │   └── models.py
│       ├── github/
│       │   ├── client.py
│       │   └── comment.py
│       └── api/
│           └── app.py
├── tests/
│   ├── fixtures/
│   │   ├── safe/
│   │   ├── review/
│   │   └── block/
│   ├── test_rules.py
│   ├── test_parser_failures.py
│   ├── test_report_contract.py
│   ├── test_runtime_inspector.py
│   └── test_github_comment.py
└── .github/
    └── workflows/
        ├── ci.yml
        └── action-smoke.yml
```

## 3. Rule engine contract

```python
from dataclasses import dataclass
from typing import Literal, Protocol


class Rule(Protocol):
    rule_id: str

    def evaluate(
        self,
        statement: "ParsedStatement",
        ctx: "AnalysisContext",
    ) -> list["Finding"]: ...


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Literal["low", "medium", "high"]
    decision: Literal["review", "block"]
    message: str
    recommendation: str
    location: "SourceLocation"
    confidence: float
    evidence: dict[str, object]
```

## 4. Data flow

```text
Developer mở PR
    |
    v
GitHub pull_request event
    |
    v
Runner checkout repository
    |
    v
Docker Action: safegate scan
    |
    +--> pglast parse SQL
    |       |
    |       v
    |   10 rule evaluators
    |
    +--> Runtime context bật?
            |
            +-- Không --> JSON report local
            |
            +-- Có ----> psycopg read-only catalog queries
                              |
                              v
                        JSON report local
    |
    v
Map status: SAFE / REVIEW / BLOCK
    |
    +--> GitHub check
    +--> Idempotent PR comment
    |
    v
BLOCK theo policy?
    |
    +-- Có --> Fail check, chặn merge
    +-- Không -> Pass hoặc yêu cầu review
```

## 5. Privacy và security boundary

- Default execution: local CLI hoặc self-hosted runner.
- Không có telemetry bắt buộc.
- GitHub chỉ nhận report/comment; source SQL không upload lên Safegate server.
- Runtime DSN truyền bằng secret/env, không commit vào repo.
- Dùng SSL và connection timeout.
- DB role chỉ có quyền connect và đọc metadata cần thiết.
- Không cấp quyền `SELECT` business tables.
- Không log DSN, token, SQL full text hoặc row data.
- Report comment nên redact identifier nhạy cảm theo policy.
- Nếu có hosted service về sau: opt-in, retention rõ, encryption, tenant isolation, audit log và DPA trước khi bán Enterprise.

## 6. Ba rủi ro kỹ thuật lớn nhất

| Rủi ro | Tác động | Mitigation cụ thể |
|---|---|---|
| False positive cao | Developer tắt gate hoặc không trả tiền | Rule có confidence/evidence; allowlist theo PG version; default REVIEW cho case thiếu context; fixture từ migration thật đã redact; đo override rate và false-positive rate |
| Parser không cover PostgreSQL syntax/version | Bỏ sót hoặc chặn migration hợp lệ | Pin `pglast`; parser failure không gắn SAFE; report `UNKNOWN`/`REVIEW`; property tests cho comments, quoted identifier, dollar-quoting; lập support matrix |
| Runtime metadata sai hoặc thiếu quyền | Đánh giá sai table size/lock; query ảnh hưởng DB | Runtime optional; read-only allowlist; `statement_timeout`/`lock_timeout`; query catalog nhẹ; timeout/permission denied thì giữ static result và nêu `UNKNOWN`; test trên replica/staging |

## 7. Các điểm cần research thêm

Trước khi tuyên bố production-safe, cần xác minh bằng tài liệu PostgreSQL chính thức và test theo các version mục tiêu:

1. Ma trận lock mode chính xác của từng statement.
2. Điều kiện fast-path của `ADD COLUMN DEFAULT`, immutable expression và khác biệt giữa PostgreSQL versions.
3. Allowlist conversion của `ALTER COLUMN TYPE` không rewrite heap/index.
4. Visibility và privilege cần thiết khi đọc `pg_locks` / `pg_stat_activity`, đặc biệt trên managed PostgreSQL.
5. Cách attach unique index concurrently thành constraint trong các migration tool cụ thể.
6. Hành vi chính xác của các rule với partitioned table, inherited table, materialized view và foreign table.

## 8. Thứ tự ship

1. **Tuần 1 — Static CLI:** JSON contract và 10 rule đầu tiên.
2. **Tuần 2 — GitHub Action:** PR comment/check và privacy boundary.
3. **Tuần 3 — Runtime context:** Read-only metadata, optional và fail-safe.
4. **Tuần 4 — Test, Docker, paid pilot:** ≥24 tests, docs và 3 design partners trả tiền.

## Quyết định kiến trúc

> Đừng bắt đầu bằng SaaS control plane hay AI. Hãy bắt đầu bằng một CLI đáng tin, chạy trong runner của khách hàng, có report JSON ổn định và một GitHub comment đủ hữu ích để reviewer không cần mở log.
