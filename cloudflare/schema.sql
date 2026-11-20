-- NoAS Cloudflare D1 表结构
-- 设计原则：D1 免费额度按"读取行数"计费，所以只存**小体量状态**，
-- 绝不把规则正文、查询日志逐条灌进来。规则正文永远走 GitHub（raw/Pages/Release）。

-- 规则版本快照：每次构建只写一行
CREATE TABLE IF NOT EXISTS build_state (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  version      TEXT    NOT NULL,
  built_at     TEXT    NOT NULL,
  lite_count   INTEGER NOT NULL DEFAULT 0,
  mid_count    INTEGER NOT NULL DEFAULT 0,
  full_count   INTEGER NOT NULL DEFAULT 0,
  wildcards    INTEGER NOT NULL DEFAULT 0,
  sha_lite     TEXT,
  note         TEXT
);

-- 白名单台账：几百条级别，可长期留在 D1 供客户端与 Worker 查询
CREATE TABLE IF NOT EXISTS allowlist (
  domain   TEXT PRIMARY KEY,
  source   TEXT NOT NULL DEFAULT 'baseline',   -- baseline / incident / issue
  note     TEXT,
  added_at TEXT NOT NULL
);

-- 端点例外（人工审计过的广告投放子域，可穿透父域白名单）
CREATE TABLE IF NOT EXISTS endpoints (
  domain   TEXT PRIMARY KEY,
  evidence TEXT,                               -- 落点域名 / prefix
  added_at TEXT NOT NULL
);

-- 签发/健康记录：只留最近若干条，定期裁剪
CREATE TABLE IF NOT EXISTS health (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  lane     TEXT NOT NULL,                      -- raw / pages / release / doh
  status   TEXT NOT NULL,                      -- ok / fail
  detail   TEXT,
  checked  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_health_checked ON health(checked);

-- 聚合计数：只存"日粒度汇总"，不存逐条请求
CREATE TABLE IF NOT EXISTS daily_stat (
  day        TEXT NOT NULL,
  tier       TEXT NOT NULL,
  blocked    INTEGER NOT NULL DEFAULT 0,
  queries    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, tier)
);
