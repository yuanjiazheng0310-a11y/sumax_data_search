-- ============================================================
-- SUMAX 查询平台 · Supabase 建表脚本
-- 在 Supabase 控制台 → SQL Editor 中整体执行一次即可
-- ============================================================

-- ① 用户表（替代 users.json，密码为加盐哈希，不存明文）
create table if not exists users (
    id            bigint generated always as identity primary key,
    username      text unique not null,
    password_hash text not null,
    display_name  text not null default '',
    role          text not null default 'user' check (role in ('admin', 'user')),
    created_at    timestamptz not null default now()
);

-- ② 操作点击明细（替代 visits.json，支持按功能类型统计）
create table if not exists action_log (
    id          bigint generated always as identity primary key,
    username    text not null,
    action_type text not null check (action_type in
        ('kit_query', 'oem_query', 'multi_to_single', 'single_to_multi', 'legacy', 'unknown')),
    created_at  timestamptz not null default now()
);
create index if not exists idx_action_user_time on action_log (username, created_at);
create index if not exists idx_action_type_time on action_log (action_type, created_at);
create index if not exists idx_action_time on action_log (created_at);

-- ③ 登录日志（替代 login_log.json，不做 500 条截断，永久保留）
create table if not exists login_attempts (
    id         bigint generated always as identity primary key,
    username   text not null default '-',
    ip         text not null default '',
    success    boolean not null default false,
    created_at timestamptz not null default now()
);
create index if not exists idx_login_time on login_attempts (created_at);
