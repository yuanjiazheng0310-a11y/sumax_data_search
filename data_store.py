# -*- coding: utf-8 -*-
"""
SUMAX 查询平台 · 数据访问层
==========================================
统一接口（Store 抽象）：
  · SupabaseStore   —— 云端持久化（部署到 Streamlit Cloud 等无状态平台不丢数据）
  · LocalJsonStore  —— 本地 json 降级（无云配置时使用，等价 app32 行为，数据不持久）

存储模式由环境变量 STORE_MODE 控制：
  · supabase：强制云端（无配置则报错）
  · local   ：强制本地 json
  · auto    ：默认。有云配置 → 云端；无配置 → 本地

密钥读取顺序：环境变量 SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY
             → streamlit secrets（.streamlit/secrets.toml 或云 Secrets）
"""
import os
import json
import hashlib
import secrets as _secrets
from datetime import datetime

import pandas as pd
from filelock import FileLock

# ----------------------------------------------------------
# 常量
# ----------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

USERS_FILE = os.path.join(BASE_DIR, "users.json")
USERS_LOCK_FILE = USERS_FILE + ".lock"
LOGIN_LOG_FILE = os.path.join(BASE_DIR, "login_log.json")
LOGIN_LOCK_FILE = LOGIN_LOG_FILE + ".lock"
ACTIONS_FILE = os.path.join(BASE_DIR, "actions_local.json")
ACTIONS_LOCK_FILE = ACTIONS_FILE + ".lock"

DEFAULT_ADMIN = "admin"
DEFAULT_ADMIN_PWD = "admin123"

MAX_LOGIN_LOG = 500          # 本地降级模式：登录日志保留条数
ACTION_TYPES = (
    "kit_query", "oem_query", "multi_to_single", "single_to_multi",
    "legacy", "unknown",
)

# ----------------------------------------------------------
# 密码工具（沿用 app32 的加盐哈希算法）
# ----------------------------------------------------------
def hash_password(password, salt=None):
    """生成加盐哈希，存储格式: salt$sha256hex"""
    if not salt:
        salt = _secrets.token_hex(8)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_password(password, stored_hash):
    """校验明文密码是否与存储的加盐哈希一致"""
    try:
        salt, digest = stored_hash.split("$", 1)
    except (ValueError, AttributeError):
        return False
    new_digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return _secrets.compare_digest(new_digest, digest)


def now_text():
    """运行环境当前时间文本"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _to_naive_local(dt):
    """把可能带时区的时间转成本机本地 naive datetime（展示与统计口径统一）"""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.astimezone().replace(tzinfo=None) if dt.tzinfo else dt
    return dt


# ----------------------------------------------------------
# 本地 json 实现（降级 / 离线 / 迁移后备份）
# ----------------------------------------------------------
class LocalJsonStore:
    name = "local"

    # ---------- 账户 ----------
    def list_users(self):
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                try:
                    os.rename(USERS_FILE, USERS_FILE + ".bak_" + datetime.now().strftime("%Y%m%d%H%M%S"))
                except OSError:
                    pass
        users = self._default_admin_users()
        self.save_users(users)
        return users

    @staticmethod
    def _default_admin_users():
        return {
            DEFAULT_ADMIN: {
                "password_hash": hash_password(DEFAULT_ADMIN_PWD),
                "display_name": "管理员",
                "role": "admin",
            }
        }

    def ensure_default_admin(self):
        users = self.list_users()
        if DEFAULT_ADMIN not in users:
            users[DEFAULT_ADMIN] = {
                "password_hash": hash_password(DEFAULT_ADMIN_PWD),
                "display_name": "管理员",
                "role": "admin",
            }
            self.save_users(users)

    def save_users(self, users):
        lock = FileLock(USERS_LOCK_FILE)
        with lock:
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                json.dump(users, f, ensure_ascii=False, indent=4)

    # ---------- 操作明细 ----------
    def record_action(self, username, action_type):
        """记录一次点击（明细行），返回 (total, today, last_text)"""
        if action_type not in ACTION_TYPES:
            action_type = "unknown"
        lock = FileLock(ACTIONS_LOCK_FILE)
        with lock:
            rows = []
            if os.path.exists(ACTIONS_FILE):
                try:
                    with open(ACTIONS_FILE, "r", encoding="utf-8") as f:
                        rows = json.load(f)
                        if not isinstance(rows, list):
                            rows = []
                except (json.JSONDecodeError, IOError):
                    rows = []
            rows.append({
                "username": username,
                "action_type": action_type,
                "time": now_text(),
            })
            try:
                with open(ACTIONS_FILE, "w", encoding="utf-8") as f:
                    json.dump(rows, f, ensure_ascii=False, indent=4)
            except IOError as e:
                print(f"保存操作明细失败: {e}")
        stats = self.get_user_stats(username)
        return stats["total"], stats["today"], stats["last"]

    def fetch_actions(self, username=None):
        """返回明细 DataFrame: [username, action_type, created_at, date]"""
        rows = []
        if os.path.exists(ACTIONS_FILE):
            try:
                with open(ACTIONS_FILE, "r", encoding="utf-8") as f:
                    rows = json.load(f)
                    if not isinstance(rows, list):
                        rows = []
            except (json.JSONDecodeError, IOError):
                rows = []
        df = pd.DataFrame(rows)
        if df.empty:
            return pd.DataFrame(columns=["username", "action_type", "created_at", "date"])
        df = df.rename(columns={"time": "created_at"})
        df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce")
        df = df.dropna(subset=["created_at"])
        if username is not None:
            df = df[df["username"] == username]
        df["date"] = df["created_at"].dt.strftime("%Y-%m-%d")
        return df.reset_index(drop=True)

    def get_user_stats(self, username):
        df = self.fetch_actions(username=username)
        today_str = datetime.now().strftime("%Y-%m-%d")
        if df.empty:
            return {"total": 0, "today": 0, "last": "-"}
        last = df["created_at"].max()
        return {
            "total": int(len(df)),
            "today": int((df["date"] == today_str).sum()),
            "last": last.strftime("%Y-%m-%d %H:%M:%S") if last is not None else "-",
        }

    # ---------- 登录日志 ----------
    def log_login(self, username, ip, success):
        try:
            lock = FileLock(LOGIN_LOCK_FILE)
            with lock:
                entries = []
                if os.path.exists(LOGIN_LOG_FILE):
                    try:
                        with open(LOGIN_LOG_FILE, "r", encoding="utf-8") as f:
                            entries = json.load(f)
                            if not isinstance(entries, list):
                                entries = []
                    except (json.JSONDecodeError, IOError):
                        entries = []
                entries.append({
                    "time": now_text(),
                    "username": (username or "").strip() or "-",
                    "ip": ip or "",
                    "success": bool(success),
                })
                entries = entries[-MAX_LOGIN_LOG:]
                with open(LOGIN_LOG_FILE, "w", encoding="utf-8") as f:
                    json.dump(entries, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"登录日志写入失败: {e}")

    def fetch_login_records(self, limit=500):
        rows = []
        if os.path.exists(LOGIN_LOG_FILE):
            try:
                with open(LOGIN_LOG_FILE, "r", encoding="utf-8") as f:
                    rows = json.load(f)
                    if not isinstance(rows, list):
                        rows = []
            except (json.JSONDecodeError, IOError):
                rows = []
        df = pd.DataFrame(rows[-limit:])
        if df.empty:
            return pd.DataFrame(columns=["time", "username", "ip", "success"])
        df["created_at"] = pd.to_datetime(df["time"], errors="coerce")
        return df.reset_index(drop=True)


# ----------------------------------------------------------
# Supabase 云端实现
# ----------------------------------------------------------
class SupabaseStore:
    name = "supabase"

    def __init__(self, url, key):
        if not url or not key:
            raise RuntimeError("Supabase 配置缺失：SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY")
        try:
            from supabase import create_client
        except ImportError:
            raise RuntimeError("缺少 supabase 依赖，请先执行：pip install -r requirements.txt")
        self._client = create_client(url, key)

    # ---------- 账户 ----------
    def list_users(self):
        resp = self._client.table("users").select("username,password_hash,display_name,role").execute()
        users = {}
        for row in resp.data:
            users[row["username"]] = {
                "password_hash": row["password_hash"],
                "display_name": row.get("display_name") or row["username"],
                "role": row.get("role") or "user",
            }
        return users

    def save_users(self, users):
        """全量 upsert 账户（以 username 为冲突键；不支持物理删除）"""
        rows = []
        for name, info in users.items():
            rows.append({
                "username": name,
                "password_hash": info.get("password_hash", ""),
                "display_name": info.get("display_name", name),
                "role": info.get("role", "user"),
            })
        if rows:
            self._client.table("users").upsert(rows, on_conflict="username").execute()

    def ensure_default_admin(self):
        resp = self._client.table("users").select("username").eq("username", DEFAULT_ADMIN).limit(1).execute()
        if not resp.data:
            self._client.table("users").insert({
                "username": DEFAULT_ADMIN,
                "password_hash": hash_password(DEFAULT_ADMIN_PWD),
                "display_name": "管理员",
                "role": "admin",
            }).execute()

    # ---------- 操作明细 ----------
    def record_action(self, username, action_type):
        if action_type not in ACTION_TYPES:
            action_type = "unknown"
        self._client.table("action_log").insert({
            "username": username,
            "action_type": action_type,
        }).execute()
        stats = self.get_user_stats(username)
        return stats["total"], stats["today"], stats["last"]

    def fetch_actions(self, username=None):
        query = self._client.table("action_log").select("username,action_type,created_at").order("created_at")
        if username is not None:
            query = query.eq("username", username)
        resp = query.execute()
        rows = resp.data or []
        df = pd.DataFrame(rows)
        if df.empty:
            return pd.DataFrame(columns=["username", "action_type", "created_at", "date"])
        df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce", utc=True)
        df["created_at"] = df["created_at"].apply(_to_naive_local)
        df = df.dropna(subset=["created_at"])
        df["date"] = df["created_at"].dt.strftime("%Y-%m-%d")
        return df.reset_index(drop=True)

    def get_user_stats(self, username):
        df = self.fetch_actions(username=username)
        today_str = datetime.now().strftime("%Y-%m-%d")
        if df.empty:
            return {"total": 0, "today": 0, "last": "-"}
        last = df["created_at"].max()
        return {
            "total": int(len(df)),
            "today": int((df["date"] == today_str).sum()),
            "last": last.strftime("%Y-%m-%d %H:%M:%S") if last is not None else "-",
        }

    # ---------- 登录日志 ----------
    def log_login(self, username, ip, success):
        self._client.table("login_attempts").insert({
            "username": (username or "").strip() or "-",
            "ip": ip or "",
            "success": bool(success),
        }).execute()

    def fetch_login_records(self, limit=500):
        resp = self._client.table("login_attempts").select("username,ip,success,created_at") \
            .order("created_at", desc=True).limit(int(limit)).execute()
        rows = resp.data or []
        rows = list(reversed(rows))
        df = pd.DataFrame(rows)
        if df.empty:
            return pd.DataFrame(columns=["time", "username", "ip", "success"])
        df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce", utc=True)
        df["created_at"] = df["created_at"].apply(_to_naive_local)
        return df.reset_index(drop=True)


# ----------------------------------------------------------
# 配置与工厂
# ----------------------------------------------------------
def _is_valid_cloud_config(url, key):
    """判断是否为可用的云配置（排除空值与 secrets 模板占位符）"""
    if not url or not key:
        return False
    if "YOUR" in url or "YOUR" in key or "TODO" in url or "TODO" in key:
        return False
    if not url.startswith("http://") and not url.startswith("https://"):
        return False
    return True


def _load_cloud_config():
    """读取 Supabase 连接配置：环境变量优先，其次 streamlit secrets"""
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if _is_valid_cloud_config(url, key):
        return url, key
    try:
        import streamlit as st
        url = st.secrets.get("SUPABASE_URL", "").strip()
        key = st.secrets.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    except Exception:
        pass
    if _is_valid_cloud_config(url, key):
        return url, key
    return "", ""


def get_store():
    """按 STORE_MODE 返回 (store 实例, 实际模式字符串)"""
    mode = os.environ.get("STORE_MODE", "auto").strip().lower()
    url, key = _load_cloud_config()
    cloud_ready = _is_valid_cloud_config(url, key)

    if mode == "supabase":
        if not cloud_ready:
            raise RuntimeError(
                "STORE_MODE=supabase 但未配置有效的 SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY。"
                "请检查 .streamlit/secrets.toml 或环境变量。"
            )
        return SupabaseStore(url, key), "supabase"
    if mode == "local":
        return LocalJsonStore(), "local"
    # auto（默认）：有有效云配置走云端；云初始化失败则安全降级本地
    if cloud_ready:
        try:
            return SupabaseStore(url, key), "supabase"
        except Exception as e:
            print(f"⚠️ Supabase 初始化失败（{e}），自动降级为本地 json 模式。")
    return LocalJsonStore(), "local"
