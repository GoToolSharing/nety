-- NETY schema. Applied by internal/store at startup; every statement must be
-- idempotent (CREATE ... IF NOT EXISTS) because migrations re-run it.

CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    display_name      TEXT    NOT NULL DEFAULT '',
    role              TEXT    NOT NULL DEFAULT 'operator',
    password_hash     TEXT    NOT NULL,
    disabled          INTEGER NOT NULL DEFAULT 0,
    must_change_pw    INTEGER NOT NULL DEFAULT 0,
    failed_attempts   INTEGER NOT NULL DEFAULT 0,
    locked_until      INTEGER,
    created_at        INTEGER NOT NULL,
    last_login_at     INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT    PRIMARY KEY,          -- hash of the session token
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    user_agent    TEXT    NOT NULL DEFAULT '',
    remote_addr   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS missions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    client        TEXT    NOT NULL DEFAULT '',
    description   TEXT    NOT NULL DEFAULT '',
    scope_cidrs   TEXT    NOT NULL DEFAULT '[]',
    exclude_cidrs TEXT    NOT NULL DEFAULT '[]',
    archived      INTEGER NOT NULL DEFAULT 0,
    created_by    INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mission_users (
    mission_id INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (mission_id, user_id)
);

CREATE TABLE IF NOT EXISTS networks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id    INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    vlan_id       INTEGER NOT NULL DEFAULT 0,
    description   TEXT    NOT NULL DEFAULT '',
    iface         TEXT    NOT NULL DEFAULT '',
    local_ip      TEXT    NOT NULL DEFAULT '',
    local_mac     TEXT    NOT NULL DEFAULT '',
    prefixes      TEXT    NOT NULL DEFAULT '[]',
    gateway       TEXT    NOT NULL DEFAULT '',
    dns_servers   TEXT    NOT NULL DEFAULT '[]',
    domain_search TEXT    NOT NULL DEFAULT '[]',
    dhcp_server   TEXT    NOT NULL DEFAULT '',
    l2            TEXT    NOT NULL DEFAULT '{}',
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    UNIQUE (mission_id, name)
);
CREATE INDEX IF NOT EXISTS idx_networks_mission ON networks(mission_id);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id  INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    network_id  INTEGER NOT NULL DEFAULT 0,
    kind        TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    options     TEXT    NOT NULL DEFAULT '{}',
    phase       TEXT    NOT NULL DEFAULT '',
    progress    REAL    NOT NULL DEFAULT 0,
    stats       TEXT    NOT NULL DEFAULT '{}',
    error       TEXT    NOT NULL DEFAULT '',
    created_by  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    started_at  INTEGER,
    paused_at   INTEGER,
    finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scans_mission ON scans(mission_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- Resumable unit of work. A scan is fully described by its rows here, so a
-- pause, a stop or a crash never loses more than the units in flight.
CREATE TABLE IF NOT EXISTS scan_work (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    phase     TEXT    NOT NULL,
    seq       INTEGER NOT NULL,
    payload   TEXT    NOT NULL,
    status    TEXT    NOT NULL DEFAULT 'pending',
    attempts  INTEGER NOT NULL DEFAULT 0,
    error     TEXT    NOT NULL DEFAULT '',
    leased_at INTEGER,
    done_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_work_claim ON scan_work(scan_id, status, phase, seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_work_unique ON scan_work(scan_id, phase, seq);

CREATE TABLE IF NOT EXISTS scan_logs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ts      INTEGER NOT NULL,
    level   TEXT    NOT NULL,
    message TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_logs ON scan_logs(scan_id, id);

CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    label      TEXT    NOT NULL DEFAULT '',
    hostname   TEXT    NOT NULL DEFAULT '',
    domain     TEXT    NOT NULL DEFAULT '',
    os         TEXT    NOT NULL DEFAULT '',
    kind       TEXT    NOT NULL DEFAULT 'unknown',
    tags       TEXT    NOT NULL DEFAULT '[]',
    notes      TEXT    NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_mission ON assets(mission_id);

CREATE TABLE IF NOT EXISTS asset_keys (
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    mission_id INTEGER NOT NULL,
    kind       TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    source     TEXT    NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (asset_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_asset_keys_lookup ON asset_keys(mission_id, kind, value);

CREATE TABLE IF NOT EXISTS asset_ips (
    asset_id   INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    mission_id INTEGER NOT NULL,
    network_id INTEGER NOT NULL,
    ip         TEXT    NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (asset_id, network_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_asset_ips_lookup ON asset_ips(mission_id, ip);

CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id    INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    network_id    INTEGER NOT NULL,
    asset_id      INTEGER NOT NULL DEFAULT 0,
    ip            TEXT    NOT NULL,
    mac           TEXT    NOT NULL DEFAULT '',
    vendor        TEXT    NOT NULL DEFAULT '',
    hostname      TEXT    NOT NULL DEFAULT '',
    hostnames     TEXT    NOT NULL DEFAULT '[]',
    domain        TEXT    NOT NULL DEFAULT '',
    os            TEXT    NOT NULL DEFAULT '',
    ttl           INTEGER NOT NULL DEFAULT 0,
    discovered_by TEXT    NOT NULL DEFAULT '[]',
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    last_scan_id  INTEGER NOT NULL DEFAULT 0,
    UNIQUE (mission_id, network_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_hosts_mission ON hosts(mission_id, network_id);
CREATE INDEX IF NOT EXISTS idx_hosts_asset ON hosts(asset_id);

CREATE TABLE IF NOT EXISTS services (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id   INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    network_id   INTEGER NOT NULL,
    host_id      INTEGER NOT NULL,
    ip           TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    protocol     TEXT    NOT NULL,
    state        TEXT    NOT NULL DEFAULT 'open',
    reason       TEXT    NOT NULL DEFAULT '',
    name         TEXT    NOT NULL DEFAULT '',
    product      TEXT    NOT NULL DEFAULT '',
    version      TEXT    NOT NULL DEFAULT '',
    extra_info   TEXT    NOT NULL DEFAULT '',
    os_type      TEXT    NOT NULL DEFAULT '',
    cpes         TEXT    NOT NULL DEFAULT '[]',
    tunnel       TEXT    NOT NULL DEFAULT '',
    banner       TEXT    NOT NULL DEFAULT '',
    tls          TEXT,
    http         TEXT,
    ssh          TEXT,
    extra        TEXT    NOT NULL DEFAULT '{}',
    confidence   INTEGER NOT NULL DEFAULT 0,
    method       TEXT    NOT NULL DEFAULT '',
    -- Operator triage. Written only through the triage endpoints, never by a
    -- scan, so re-scanning a network never erases the manual pass over it.
    triage_status    TEXT    NOT NULL DEFAULT 'todo',
    triage_note      TEXT    NOT NULL DEFAULT '',
    triage_by        INTEGER NOT NULL DEFAULT 0,
    triage_at        INTEGER,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    last_scan_id INTEGER NOT NULL DEFAULT 0,
    UNIQUE (mission_id, network_id, ip, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_services_mission ON services(mission_id, network_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(mission_id, port);
-- idx_services_triage is created by the migration, not here. This file runs
-- against existing databases too, where the triage columns do not exist yet
-- (migrations run after it), and indexing a missing column fails the startup.

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id   INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    network_id   INTEGER NOT NULL,
    host_id      INTEGER NOT NULL DEFAULT 0,
    service_id   INTEGER NOT NULL DEFAULT 0,
    ip           TEXT    NOT NULL,
    port         INTEGER NOT NULL DEFAULT 0,
    protocol     TEXT    NOT NULL DEFAULT '',
    check_id     TEXT    NOT NULL,
    title        TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    description  TEXT    NOT NULL DEFAULT '',
    evidence     TEXT    NOT NULL DEFAULT '',
    remediation  TEXT    NOT NULL DEFAULT '',
    refs         TEXT    NOT NULL DEFAULT '[]',
    -- Operator triage. Written only through the triage endpoints, never by a
    -- scan, so re-running the checks never erases the manual verdict on them.
    triage_status TEXT    NOT NULL DEFAULT 'todo',
    triage_note   TEXT    NOT NULL DEFAULT '',
    triage_by     INTEGER NOT NULL DEFAULT 0,
    triage_at     INTEGER,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    last_scan_id INTEGER NOT NULL DEFAULT 0,
    UNIQUE (mission_id, network_id, ip, port, protocol, check_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_mission ON findings(mission_id, severity);
-- idx_findings_triage is created by the migration, not here, for the same
-- reason as idx_services_triage above: this file also runs against databases
-- that predate the triage columns.

CREATE TABLE IF NOT EXISTS reach_results (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id        INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    scan_id           INTEGER NOT NULL DEFAULT 0,
    source_network_id INTEGER NOT NULL,
    target_network_id INTEGER NOT NULL,
    target_host_id    INTEGER NOT NULL DEFAULT 0,
    target_service_id INTEGER NOT NULL DEFAULT 0,
    ip                TEXT    NOT NULL,
    port              INTEGER NOT NULL DEFAULT 0,
    protocol          TEXT    NOT NULL DEFAULT '',
    technique         TEXT    NOT NULL,
    vlan_id           INTEGER NOT NULL DEFAULT 0,
    status            TEXT    NOT NULL,
    detail            TEXT    NOT NULL DEFAULT '',
    rtt_ms            REAL    NOT NULL DEFAULT 0,
    tested_at         INTEGER NOT NULL,
    UNIQUE (mission_id, source_network_id, ip, port, protocol, technique, vlan_id)
);
CREATE INDEX IF NOT EXISTS idx_reach_matrix ON reach_results(mission_id, source_network_id, target_network_id);
CREATE INDEX IF NOT EXISTS idx_reach_scan ON reach_results(scan_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    user_id    INTEGER NOT NULL DEFAULT 0,
    username   TEXT    NOT NULL DEFAULT '',
    mission_id INTEGER NOT NULL DEFAULT 0,
    action     TEXT    NOT NULL,
    detail     TEXT    NOT NULL DEFAULT '',
    remote     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
