# -*- coding: utf-8 -*-
# @Time : 2026-09-03
# @Author : ZJY
# @File : app33.py（云存储版 · 基于 app32.py 改造，保留 app31/app32 原文件不动）
# @Software : PyCharm
# @Description ：SUMAX 汽配查询平台 —— 登录验证门禁 + 账户维度操作统计
#              · 数据存储：Supabase 云端持久化（部署到 Streamlit Cloud 不丢数据），
#                未配置云时自动降级为本地 json（STORE_MODE: supabase / local / auto）
#              · 统计口径：登录账户点击按钮即计入该账户 1 次，且记录功能类型
#               ① 📦 查询套装(kit_query) ② ⚙️ 查询零件(oem_query)
#               ③ 多行转单行(multi_to_single) ④ 单行转多行(single_to_multi)
#              · 普通用户可自助修改本人密码（需校验原密码），仅能改自己
#              · 管理员独享：账户管理 + 全局统计图表面板（KPI / 柱状图 / 趋势图）
#
# 启动方式（端口 9999）：
#   cd d:/AI/ai_dev/sumax
#   python -m streamlit run app33.py --server.port 9999
# 或直接双击 run_9999_app33.bat
#
# 云部署前必做：
#   1) Supabase SQL Editor 执行 db/schema.sql 完成建表；
#   2) 本地开发填 .streamlit/secrets.toml；云端部署在 Streamlit Cloud → Secrets 填写
#      SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY
#   3) 历史数据导入：python migrate_local_to_supabase.py
# 默认管理员：admin / admin123（登录后请尽快在侧边栏修改密码）

import os
import time
import base64
import hashlib
import secrets
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

# 数据访问层：云端 Supabase 为主、本地 json 降级（STORE_MODE: supabase / local / auto）
from data_store import get_store

store, store_mode = get_store()
CLOUD_READY = store_mode == "supabase"

# ==========================================
# 📁 常量与文件路径
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKGROUND_IMAGE_FILE = os.path.join(BASE_DIR, "跑车.jpg")

DEFAULT_ADMIN = "admin"
DEFAULT_ADMIN_PWD = "admin123"


# ==========================================
# 🔐 账户模块（users.json）
# ==========================================
def hash_password(password, salt=None):
    """生成加盐哈希，存储格式: salt$sha256hex"""
    if not salt:
        salt = secrets.token_hex(8)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_password(password, stored_hash):
    """校验明文密码是否与存储的加盐哈希一致"""
    try:
        salt, digest = stored_hash.split("$", 1)
    except (ValueError, AttributeError):
        return False
    new_digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return secrets.compare_digest(new_digest, digest)


def load_users():
    """读取账户表（数据来自当前存储：Supabase 云端或本地 json）"""
    return store.list_users()


def save_users(users):
    """保存账户表（写入当前存储）"""
    store.save_users(users)


def authenticate(username, password):
    """验证登录，成功返回用户信息 dict，失败返回 (None, 错误信息)"""
    username = (username or "").strip()
    users = load_users()
    user = users.get(username)
    if user is None:
        return None, "用户名不存在"
    if not verify_password(password or "", user.get("password_hash", "")):
        return None, "密码错误"
    return {
        "username": username,
        "display_name": user.get("display_name", username),
        "role": user.get("role", "user"),
    }, None


def is_default_admin_password(username):
    """检测指定账户是否仍在使用默认初始密码"""
    if username != DEFAULT_ADMIN:
        return False
    users = load_users()
    user = users.get(username)
    if not user:
        return False
    return verify_password(DEFAULT_ADMIN_PWD, user.get("password_hash", ""))


# ==========================================
# 📈 操作统计模块（明细化：记录功能类型，统计走当前存储）
# ==========================================
def record_visit(username, action_type):
    """记录当前账户一次功能按钮点击（含功能类型），返回 (总次数, 今日次数, 操作时间)"""
    try:
        return store.record_action(username, action_type)
    except Exception as e:
        print(f"记录操作失败: {e}")
        return 0, 0, "-"


def get_user_stats(username):
    """读取某账户的统计，未记录过时返回默认值"""
    try:
        return store.get_user_stats(username)
    except Exception as e:
        print(f"读取统计失败: {e}")
    return {"total": 0, "today": 0, "last": "-"}


# ==========================================
# 📝 登录日志模块（login_log.json）
# ==========================================
def get_client_ip():
    """获取访问者的 IP 地址"""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        from streamlit.runtime import get_instance
        ctx = get_script_run_ctx()
        if ctx is None:
            return "127.0.0.1"
        session_info = get_instance().get_client(ctx.session_id)
        if session_info is None:
            return "127.0.0.1"
        request = session_info.request
        ip = request.headers.get("X-Real-Ip")
        if not ip:
            ip = request.headers.get("X-Forwarded-For")
        if not ip:
            ip = request.remote_ip
        return ip
    except Exception:
        return "127.0.0.1"


def log_login(username, success):
    """记录一次登录尝试（成功/失败），写入当前存储（云库/本地日志）"""
    try:
        store.log_login(username, get_client_ip(), bool(success))
    except Exception as e:
        print(f"登录日志写入失败: {e}")


def ensure_default_admin_safe():
    """确保默认管理员存在；存储不可用时返回错误信息（不中断整个应用）"""
    try:
        store.ensure_default_admin()
        return True, None
    except Exception as e:
        return False, str(e)


def change_my_password(username, old_pwd, new_pwd):
    """自助修改本人密码（需校验原密码），返回 (是否成功, 提示文字)"""
    if not old_pwd:
        return False, "请输入原密码。"
    if not new_pwd or len(new_pwd) < 4:
        return False, "新密码长度至少 4 位。"
    users = load_users()
    user = users.get(username)
    if user is None:
        return False, "账户不存在。"
    if not verify_password(old_pwd, user.get("password_hash", "")):
        return False, "原密码错误。"
    if old_pwd == new_pwd:
        return False, "新密码不能与原密码相同。"
    user["password_hash"] = hash_password(new_pwd)
    save_users(users)
    return True, "密码已修改，下次登录请使用新密码。"


# ==========================================
# 🖼️ 背景图片与 CSS
# ==========================================
def get_base64_of_image(file_path):
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode()
    except Exception as e:
        print(f"图片读取错误: {e}")
        return None


img_base64 = get_base64_of_image(BACKGROUND_IMAGE_FILE)

if img_base64:
    bg_css = f"""
    .stApp {{
        background-image: url("data:image/jpg;base64,{img_base64}");
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        background-attachment: fixed;
    }}
    """
else:
    bg_css = """
    .stApp {
        background: linear-gradient(135deg, #14142b 0%, #2d2b55 60%, #3a1a2f 100%);
    }
    """

BASE_CSS = f"""
<style>
{bg_css}
.stApp {{ background-color: transparent; }}
/* 隐藏右上菜单与页脚，界面更干净 */
#MainMenu, footer {{ visibility: hidden; }}
[data-testid="stHeader"] {{ background: transparent; }}

/* 主界面侧边栏：半透明毛玻璃 */
[data-testid="stSidebar"] {{
    background-color: rgba(10, 10, 25, 0.62);
    backdrop-filter: blur(10px);
    border-right: 1px solid rgba(255, 255, 255, 0.08);
}}

/* 输入框：白底黑字，阅读清晰 */
.stTextInput input, .stTextArea textarea {{
    background-color: #FFFFFF !important;
    color: #1a1a1a !important;
    border-radius: 8px;
}}
.stTextInput input::placeholder, .stTextArea textarea::placeholder {{
    color: #999999 !important;
    opacity: 1;
}}

/* 主按钮：品牌红色渐变 */
[data-testid="stBaseButton-primaryFormSubmit"],
[data-testid="stBaseButton-primary"] {{
    background: linear-gradient(135deg, #FF4B4B 0%, #ff6a3d 100%) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 8px !important;
    box-shadow: 0 6px 18px rgba(255, 75, 75, 0.35);
    font-weight: 600;
}}
[data-testid="stBaseButton-primaryFormSubmit"]:hover,
[data-testid="stBaseButton-primary"]:hover {{
    background: linear-gradient(135deg, #e63333 0%, #f25a2e 100%) !important;
}}

/* 次要按钮：玻璃描边 */
[data-testid="stBaseButton-secondaryFormSubmit"],
[data-testid="stBaseButton-secondary"] {{
    background: rgba(255, 255, 255, 0.10) !important;
    color: #ffffff !important;
    border: 1px solid rgba(255, 255, 255, 0.35) !important;
    border-radius: 8px !important;
    backdrop-filter: blur(4px);
}}

/* 文本域拖拽调整高度 */
.stTextArea textarea {{
    resize: vertical !important;
    min-height: 100px;
    max-height: 500px;
}}

/* metric 卡片微调 */
[data-testid="stMetric"] {{
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 12px;
    padding: 10px 12px;
}}
[data-testid="stMetricValue"] {{ color: #ff6a4d !important; }}
</style>
"""

LOGIN_CSS = f"""
<style>
/* 登录页隐藏侧边栏 */
[data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"] {{ display: none !important; }}

/* 品牌区 */
.login-brand {{
    text-align: center;
    margin: 5vh 0 1.6rem 0;
}}
.login-logo {{
    font-size: 3.4rem;
    line-height: 1.1;
    filter: drop-shadow(0 8px 18px rgba(255, 90, 60, 0.45));
}}
.login-title {{
    font-size: 1.9rem;
    font-weight: 800;
    letter-spacing: 1px;
    background: linear-gradient(135deg, #ffffff 30%, #ffb199 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0.4rem 0 0.1rem;
}}
.login-sub {{
    color: rgba(255, 255, 255, 0.60);
    font-size: 0.85rem;
    letter-spacing: 2px;
}}

/* 登录卡片 */
[data-testid="stForm"] {{
    background: rgba(12, 12, 28, 0.62);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 20px;
    padding: 2.0rem 2.2rem 1.8rem 2.2rem;
    box-shadow: 0 24px 70px rgba(0, 0, 0, 0.5);
}}

/* 登录表单内的文字颜色 */
[data-testid="stForm"] label p {{
    color: rgba(255, 255, 255, 0.85) !important;
    font-weight: 600;
}}

/* 提示文字 */
.login-hint {{
    text-align: center;
    color: rgba(255, 255, 255, 0.45);
    font-size: 0.78rem;
    margin-top: 1.1rem;
}}
.login-error {{
    color: #ff8a80;
}}
</style>
"""


# ==========================================
# 📊 数据加载与查询工具（沿用 app31 的优化实现）
# ==========================================
@st.cache_data
def load_data():
    data = {}
    try:
        file_path_1 = os.path.join(BASE_DIR, "1.parquet")
        file_path_2 = os.path.join(BASE_DIR, "2.parquet")

        if os.path.exists(file_path_1):
            df_kit = pd.read_parquet(file_path_1)
            df_kit.columns = df_kit.columns.str.strip()
            if "套装编号" in df_kit.columns and "配件编号" in df_kit.columns:
                df_kit["套装编号"] = df_kit["套装编号"].astype(str).str.strip()
                df_kit["配件编号"] = df_kit["配件编号"].astype(str).str.strip()
            data["kit"] = df_kit

        if os.path.exists(file_path_2):
            df_part = pd.read_parquet(file_path_2)
            df_part.columns = df_part.columns.str.strip()
            if "零件编号" not in df_part.columns:
                df_part["零件编号"] = ""
            if "OEM编号" not in df_part.columns:
                df_part["OEM编号"] = ""
            df_part["OEM编号"] = df_part["OEM编号"].astype(str).str.strip()
            df_part["零件编号"] = df_part["零件编号"].astype(str).str.strip()
            df_part = df_part[df_part["OEM编号"] != "nan"]
            df_part = df_part[df_part["OEM编号"] != ""]
            data["part"] = df_part
        return data
    except Exception as e:
        st.error(f"数据加载失败: {str(e)}")
        return data


@st.cache_data
def preprocess_part_data(df_part):
    """预处理零件数据，预计算查询所需结构（性能优化）"""
    if df_part.empty:
        return {}, pd.DataFrame()

    df_part = df_part.copy()
    df_part["oem_len"] = df_part["OEM编号"].str.len()

    len_groups = {}
    for length in df_part["oem_len"].unique():
        len_groups[length] = df_part[df_part["oem_len"] == length]

    oem_to_parts = df_part.groupby("OEM编号")["零件编号"].apply(list).to_dict()
    oem_len_map = df_part.set_index("OEM编号")["oem_len"].to_dict()

    return {
        "len_groups": len_groups,
        "oem_to_parts": oem_to_parts,
        "oem_len_map": oem_len_map,
        "df_part": df_part,
    }, df_part


def clean_oem(oem_str):
    """清理 OEM 编号中的横杠、空格、点号"""
    return oem_str.replace("-", "").replace(" ", "").replace(".", "")


def check_limit(text, limit=100):
    lines = [x for x in text.strip().split("\n") if x.strip()]
    return len(lines)


def format_search_results(results_df, success_msg=None):
    if results_df.empty:
        st.warning("未找到任何结果。")
        return False
    else:
        if success_msg:
            st.success(success_msg)
        else:
            st.success(f"找到 {len(results_df)} 条结果！")
        st.dataframe(results_df, use_container_width=True, hide_index=True)
        return True


# ==========================================
# 🔐 登录页 UI
# ==========================================
def render_login_page():
    st.markdown(LOGIN_CSS, unsafe_allow_html=True)

    col_l, col_m, col_r = st.columns([1, 1.05, 1])
    with col_m:
        st.markdown(
            """
            <div class="login-brand">
                <div class="login-logo">📦</div>
                <div class="login-title">SUMAX 汽配查询平台</div>
                <div class="login-sub">AUTO PARTS SUITE QUERY SYSTEM</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # “显示密码”复选框需放在表单外，切换时即时生效
        show_pwd = st.checkbox("显示密码", key="login_show_pwd", value=False)

        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("👤 用户名", placeholder="请输入用户名", key="login_user")
            if show_pwd:
                password = st.text_input("🔑 密码", key="login_pwd_plain", placeholder="请输入密码")
            else:
                password = st.text_input("🔑 密码", type="password", key="login_pwd_masked", placeholder="请输入密码")

            col_b1, col_b2 = st.columns(2)
            do_login = col_b1.form_submit_button("登  录", type="primary", use_container_width=True)
            do_reset = col_b2.form_submit_button("重  置", use_container_width=True)

        if do_reset:
            # widget 已实例化后不能直接赋新值，需先删除对应 key 使其重建为空
            for key in ("login_user", "login_pwd_plain", "login_pwd_masked"):
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()

        if do_login:
            user, err = authenticate(username, password)
            if user:
                log_login(username, True)
                for key in ("login_user", "login_pwd_plain", "login_pwd_masked"):
                    if key in st.session_state:
                        del st.session_state[key]
                st.session_state["logged_in"] = True
                st.session_state["user"] = user
                st.rerun()
            else:
                log_login(username, False)
                st.error(f"❌ 登录失败：{err}")

        st.markdown(
            '<div class="login-hint">默认管理员：admin&nbsp;/&nbsp;admin123<br>'
            "登录后请在侧边栏「修改我的密码」中尽快修改初始密码</div>",
            unsafe_allow_html=True,
        )


# ==========================================
# 👥 账户管理（仅管理员）
# ==========================================
def render_account_manager():
    users = load_users()
    st.markdown("**👥 账户管理**")

    if is_default_admin_password(DEFAULT_ADMIN):
        st.warning("⚠️ 正在使用初始密码 admin/admin123，请尽快修改！")

    tab_add, tab_reset = st.tabs(["➕ 新增用户", "🔑 修改/重置密码"])

    with tab_add:
        with st.form("form_add_user", clear_on_submit=True):
            new_name = st.text_input("用户名（登录账号）", key="au_name")
            new_display = st.text_input("显示名称（如：张三）", key="au_display")
            new_pwd = st.text_input("初始密码", type="password", key="au_pwd")
            new_role = st.selectbox("角色", ["user", "admin"], index=0,
                                    format_func=lambda r: "管理员" if r == "admin" else "普通用户")
            submitted_add = st.form_submit_button("✔️ 创建账户", type="primary", use_container_width=True)

        if submitted_add:
            name = (new_name or "").strip()
            if not name or not new_pwd:
                st.error("用户名与初始密码不能为空。")
            elif name in users:
                st.error(f"账户 [{name}] 已存在。")
            elif len(new_pwd) < 4:
                st.error("密码长度至少 4 位。")
            else:
                users[name] = {
                    "password_hash": hash_password(new_pwd),
                    "display_name": (new_display or "").strip() or name,
                    "role": new_role,
                }
                save_users(users)
                st.success(f"✅ 账户 [{name}] 创建成功。")

    with tab_reset:
        other_users = [u for u in users.keys() if u != DEFAULT_ADMIN]
        target_default = DEFAULT_ADMIN
        if other_users:
            with st.form("form_reset_pwd"):
                target = st.selectbox("选择账户", [DEFAULT_ADMIN] + other_users,
                                      format_func=lambda u: f"{u}（{users[u].get('display_name', u)}）")
                new_pwd2 = st.text_input("设置新密码", type="password", key="rp_pwd")
                submitted_reset = st.form_submit_button("💾 保存新密码", type="primary", use_container_width=True)
        else:
            target = target_default
            with st.form("form_reset_pwd"):
                new_pwd2 = st.text_input("设置新密码", type="password", key="rp_pwd")
                submitted_reset = st.form_submit_button("💾 保存新密码", type="primary", use_container_width=True)

        if submitted_reset:
            if not new_pwd2 or len(new_pwd2) < 4:
                st.error("密码长度至少 4 位。")
            else:
                users[target]["password_hash"] = hash_password(new_pwd2)
                save_users(users)
                st.success(f"✅ 账户 [{target}] 密码已更新。")
                if target == st.session_state.user["username"]:
                    st.info("您已修改当前账户密码，下次登录请使用新密码。")


# ==========================================
# 📊 管理员统计面板（主界面顶部，仅管理员可见）
# ==========================================
ACTION_TYPE_NAMES = {
    "kit_query": "查询套装",
    "oem_query": "查询零件",
    "multi_to_single": "多行转单行",
    "single_to_multi": "单行转多行",
    "legacy": "历史数据",
    "unknown": "未知",
}


def render_admin_dashboard():
    """管理员全局统计：KPI 指标 + 5 类图表 + 明细表"""
    st.markdown("---")
    st.subheader("📊 管理员统计面板")
    st.caption("仅管理员可见。口径：任意账户点击功能按钮计 1 次操作（含功能类型）。")

    try:
        df_act = store.fetch_actions()
        df_login = store.fetch_login_records(limit=2000)
    except Exception as e:
        st.error(f"⚠️ 读取统计数据失败：{e}")
        return

    today_str = datetime.now().strftime("%Y-%m-%d")

    # ---------- KPI ----------
    n_accounts = len(load_users())
    if df_act.empty:
        total_ops = today_ops = today_users = 0
    else:
        total_ops = int(len(df_act))
        today_ops = int((df_act["date"] == today_str).sum())
        today_users = int(df_act.loc[df_act["date"] == today_str, "username"].nunique())
    if df_login.empty or "success" not in df_login.columns:
        ok_logins = fail_logins = 0
    else:
        ok_logins = int(df_login["success"].astype(bool).sum())
        fail_logins = int((~df_login["success"].astype(bool)).sum())

    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("👥 总账户数", n_accounts)
    k2.metric("🔥 今日活跃账户", today_users)
    k3.metric("📦 累计操作次数", total_ops)
    k4.metric("📅 今日操作次数", today_ops)
    k5.metric("✅ 登录成功", ok_logins)
    k6.metric("⚠️ 登录失败", fail_logins)

    tab_rank, tab_trend, tab_type, tab_type_trend, tab_login, tab_table = st.tabs(
        ["① 账户排行", "② 操作趋势", "③ 功能分类", "④ 功能趋势", "⑤ 登录分析", "⑥ 明细表"])

    # ① 账户排行
    with tab_rank:
        c1, c2 = st.columns([1, 2])
        rank_mode = c1.radio("统计口径", ["累计", "今日"], horizontal=True, key="panel_rank_mode")
        top_n = c2.select_slider("显示前 N 名", options=[5, 10, 15, 20, 30], value=10, key="panel_rank_top")
        if df_act.empty:
            st.info("暂无操作数据。")
        else:
            sub = df_act[df_act["date"] == today_str] if rank_mode == "今日" else df_act
            ser = sub.groupby("username").size().sort_values(ascending=False).head(int(top_n))
            if ser.empty:
                st.info("该口径下暂无操作数据。")
            else:
                st.bar_chart(ser.rename("操作次数").to_frame(), height=360)

    # ② 操作趋势
    with tab_trend:
        range_opt = st.radio("时间范围", ["近 7 天", "近 30 天", "全部"],
                             horizontal=True, key="panel_trend_range")
        if df_act.empty:
            st.info("暂无操作数据。")
        else:
            ser = df_act.groupby("date").size()
            if range_opt != "全部":
                start_day = (datetime.now() - timedelta(days=7 if "7" in range_opt else 30)).strftime("%Y-%m-%d")
                ser = ser[ser.index >= start_day]
            if ser.empty:
                st.info("该时间范围内暂无操作数据。")
            else:
                date_axis = [d.strftime("%Y-%m-%d")
                             for d in pd.date_range(ser.index.min(), today_str)]
                st.area_chart(ser.reindex(date_axis, fill_value=0).rename("每日操作次数").to_frame(), height=360)

    # ③ 功能分类
    with tab_type:
        excl_legacy = st.checkbox("排除历史数据(legacy)", value=True, key="panel_type_excl")
        if df_act.empty:
            st.info("暂无操作数据。")
        else:
            sub = df_act[df_act["action_type"] != "legacy"] if excl_legacy else df_act
            ser = sub.groupby("action_type").size().sort_values(ascending=False)
            ser.index = [ACTION_TYPE_NAMES.get(x, x) for x in ser.index]
            if ser.empty:
                st.info("当前筛选下无数据。")
            else:
                st.bar_chart(ser.rename("操作次数").to_frame(), height=360)

    # ④ 功能趋势（近 30 天）
    with tab_type_trend:
        if df_act.empty:
            st.info("暂无操作数据。")
        else:
            start_day = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
            sub = df_act[df_act["date"] >= start_day]
            if sub.empty:
                st.info("近 30 天暂无操作数据。")
            else:
                pivot = sub.pivot_table(index="date", columns="action_type", values="created_at",
                                        aggfunc="count", fill_value=0)
                pivot.columns = [ACTION_TYPE_NAMES.get(x, x) for x in pivot.columns]
                st.line_chart(pivot, height=360)

    # ⑤ 登录分析
    with tab_login:
        if df_login.empty:
            st.info("暂无登录记录。")
        else:
            dfl = df_login.copy()
            dfl["date"] = dfl["created_at"].dt.strftime("%Y-%m-%d")
            pivot = dfl.pivot_table(index="date", columns="success", values="created_at",
                                    aggfunc="count", fill_value=0)
            pivot = pivot.rename(columns={True: "成功", False: "失败"})
            for col in ("成功", "失败"):
                if col not in pivot.columns:
                    pivot[col] = 0
            st.bar_chart(pivot[["成功", "失败"]], height=360)

    # ⑥ 明细表
    with tab_table:
        if df_act.empty:
            st.info("暂无操作数据。")
        else:
            agg = df_act.groupby("username").agg(历史累计=("username", "size"),
                                                 最近操作=("created_at", "max")).reset_index()
            agg["最近操作"] = agg["最近操作"].dt.strftime("%Y-%m-%d %H:%M:%S")
            today_count = df_act[df_act["date"] == today_str].groupby("username").size().rename("今日")
            agg = agg.merge(today_count.reset_index(), on="username", how="left")
            agg["今日"] = agg["今日"].fillna(0).astype(int)
            agg = agg.sort_values("历史累计", ascending=False)
            st.markdown("**账户汇总**")
            st.dataframe(agg, use_container_width=True, hide_index=True)

            st.markdown("**账户 × 功能类型**")
            piv2 = df_act.pivot_table(index="username", columns="action_type", values="created_at",
                                      aggfunc="count", fill_value=0).reset_index()
            piv2.columns = ["账户"] + [ACTION_TYPE_NAMES.get(x, x) for x in piv2.columns[1:]]
            st.dataframe(piv2, use_container_width=True, hide_index=True)


# ==========================================
# 📊 侧边栏统计展示（当前账户）
# ==========================================
# 这些占位对象在登录后的侧边栏中创建，按钮点击后刷新
PH_TODAY = None
PH_TOTAL = None
PH_LAST = None


def refresh_user_stats_ui():
    """刷新侧边栏中当前账户的今日/累计/最近操作统计"""
    if PH_TODAY is None:
        return
    user = st.session_state.get("user")
    if not user:
        return
    stats = get_user_stats(user["username"])
    PH_TODAY.success(f"📅 今日操作：**{stats['today']}** 次")
    PH_TOTAL.info(f"📦 历史累计：**{stats['total']}** 次")
    PH_LAST.caption(f"🕐 最近操作：{stats['last']}")


def do_count_once(action_type="unknown"):
    """功能按钮点击计数（携带功能类型）并刷新侧边栏，返回 (total, today, now)"""
    user = st.session_state.get("user")
    if not user:
        return 0, 0, "-"
    total, today, now_str = record_visit(user["username"], action_type)
    refresh_user_stats_ui()
    return total, today, now_str


# ==========================================
# 🚀 页面入口
# ==========================================
st.set_page_config(
    page_title="SUMAX 汽配查询平台（登录版）",
    page_icon="📦",
    layout="wide",
)

st.markdown(BASE_CSS, unsafe_allow_html=True)

# 确保默认管理员存在（首次启动自动写入 admin/admin123）
admin_ok, admin_err = ensure_default_admin_safe()
if not admin_ok:
    st.error(
        f"⚠️ 无法连接数据存储：{admin_err}\n\n"
        "请检查：① Supabase 项目是否已执行 db/schema.sql 建表；"
        "② .streamlit/secrets.toml（本地）或 Streamlit Cloud Secrets 是否填写了 "
        "SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY。\n\n"
        "如需强制本地模式运行，可设置环境变量 STORE_MODE=local。"
    )
    st.stop()

# 会话初始化
st.session_state.setdefault("logged_in", False)
st.session_state.setdefault("user", None)

# ---------- 未登录：仅展示登录页 ----------
if not st.session_state["logged_in"]:
    render_login_page()
    st.stop()

# ==========================================
# ✅ 已登录：查询主界面
# ==========================================
user_session = st.session_state["user"]
is_admin = user_session["role"] == "admin"
display_name = user_session.get("display_name", user_session["username"])
username = user_session["username"]

# ---------- 加载与预处理数据 ----------
data_sources = load_data()
df_kit = data_sources.get("kit", pd.DataFrame())
df_part = data_sources.get("part", pd.DataFrame())
precomputed_data, df_part_processed = preprocess_part_data(df_part)
len_groups = precomputed_data.get("len_groups", {})
oem_to_parts = precomputed_data.get("oem_to_parts", {})
oem_len_map = precomputed_data.get("oem_len_map", {})

# ==========================================
# 📝 侧边栏
# ==========================================
with st.sidebar:
    st.header("📊 SUMAX 查询平台")

    # 当前登录用户区
    st.markdown(f"**👤 {display_name}**")
    st.caption(f"账号：{username}　|　角色：{'管理员' if is_admin else '普通用户'}")

    # 存储模式提示
    if CLOUD_READY:
        st.caption("☁️ 已连接云端数据库（Supabase）")
    else:
        st.caption("⚠️ 本地模式：数据存于本机 json，云端部署请配置 Supabase")

    PH_TODAY = st.empty()
    PH_TOTAL = st.empty()
    PH_LAST = st.empty()
    refresh_user_stats_ui()

    # 🔑 修改我的密码（管理员与普通用户均可，仅能修改自己）
    with st.expander("🔑 修改我的密码"):
        with st.form("form_change_my_pwd"):
            pwd_old = st.text_input("原密码", type="password", key="cmp_pwd_old")
            pwd_new = st.text_input("新密码（至少 4 位）", type="password", key="cmp_pwd_new")
            pwd_new2 = st.text_input("确认新密码", type="password", key="cmp_pwd_new2")
            do_change_pwd = st.form_submit_button("💾 保存新密码", type="primary", use_container_width=True)
        if do_change_pwd:
            if not pwd_old or not pwd_new or not pwd_new2:
                st.warning("请完整填写原密码与新密码。")
            elif pwd_new != pwd_new2:
                st.error("❌ 两次输入的新密码不一致。")
            else:
                ok_change, msg_change = change_my_password(username, pwd_old, pwd_new)
                if ok_change:
                    st.success(f"✅ {msg_change}")
                else:
                    st.error(f"❌ {msg_change}")

    if st.button("🚪 退出登录", use_container_width=True):
        st.session_state["logged_in"] = False
        st.session_state["user"] = None
        st.rerun()

    st.markdown("---")

    if not df_kit.empty:
        unique_kit_count = df_kit.iloc[:, 0].nunique()
        st.metric("总套装记录数 📦", unique_kit_count)

    if not df_part.empty:
        unique_part_count = df_part.iloc[:, 0].nunique()
        st.metric("含 OEM 产品总数 📦", unique_part_count)

    st.markdown("---")

    # 管理员：账户管理
    if is_admin:
        render_account_manager()
        st.markdown("---")
        st.caption("📊 全局统计图表已移至主界面顶部「管理员统计面板」。")

    st.markdown("---")
    st.info("💡 提示1：输入框支持鼠标拖拽调整高度。")
    st.info("💡 提示2：智能识别 OEM 编号，自动忽略空格、横杠及点号。")
    st.warning("⚠️ 限制：套装单次最多 100 条；OEM 查询单次限 1000 行。")

# ==========================================
# 📊 管理员统计面板（仅管理员可见，位于主界面顶部）
# ==========================================
if is_admin:
    render_admin_dashboard()

# ==========================================
# 🔧 套装查询
# ==========================================
st.subheader("🔧 套装查询")
col1_kit, col2_kit = st.columns([3, 1])

with col1_kit:
    search_text_kit = st.text_area(
        "🔍 输入配件编号",
        placeholder="支持批量查询，请换行分隔：\nTC1445\nTG1891",
        key="kit_input",
        label_visibility="visible",
    )

with col2_kit:
    mode_kit = st.radio(
        "匹配模式:",
        ["精确匹配 (严格)", "包含匹配 (宽泛)"],
        horizontal=False,
        key="kit_mode",
    )

if st.button("📦 查询套装", type="primary"):
    # 登录账户计数：点击按钮即计 1 次（类型：套装查询）
    total_visits, today_visits, _ = do_count_once("kit_query")

    if not df_kit.empty and search_text_kit.strip():
        line_count = check_limit(search_text_kit, 100)
        if line_count > 100:
            st.error(f"❌ 输入数据过多！当前 {line_count} 行，单次查询不得超过 100 条。")
            st.stop()

        query_parts = [x.strip() for x in search_text_kit.strip().split("\n") if x.strip()]
        query_set = set(query_parts)
        results = []
        grouped = df_kit.groupby("套装编号")["配件编号"].apply(set).reset_index()
        grouped.columns = ["套装编号", "kit_parts_set"]

        if "包含匹配" in mode_kit:
            for _, row in grouped.iterrows():
                kit_parts = row["kit_parts_set"]
                if query_set.issubset(kit_parts):
                    results.append({
                        "套装编号": row["套装编号"],
                        "匹配零件数": len(query_set),
                        "套装总零件数": len(kit_parts),
                    })
        else:
            for _, row in grouped.iterrows():
                kit_parts = row["kit_parts_set"]
                if kit_parts == query_set:
                    results.append({
                        "套装编号": row["套装编号"],
                        "匹配零件数": len(query_set),
                    })

        if results:
            st.success(f"找到 {len(results)} 个符合条件的套装！")
            st.dataframe(pd.DataFrame(results), use_container_width=True)
        else:
            st.warning("未找到匹配的套装。")
    elif df_kit.empty:
        st.error("套装数据未加载，请检查 Parquet 文件。")
    else:
        st.warning("请输入配件编号。")

st.markdown("---")

# ==========================================
# 🔎 OEM 零件查询（优化版）
# ==========================================
st.subheader("🔍 OEM 零件查询")
col1_oem, col2_oem = st.columns([3, 1])

with col1_oem:
    search_text_oem = st.text_area(
        "🔍 输入 OEM 编号",
        placeholder="支持批量查询，请换行分隔：\n38810\n926003",
        key="oem_input",
        label_visibility="visible",
    )

with col2_oem:
    mode_oem = st.radio(
        "匹配模式:",
        ["精确匹配", "宽泛匹配 (包含+长度差≤1)"],
        horizontal=False,
        key="oem_mode",
        help="宽泛匹配规则：\n1. 字符串互相包含\n2. 长度差不能超过 1 位",
    )

if st.button("⚙️ 查询零件", type="primary"):
    start_time = time.time()

    # 登录账户计数：点击按钮即计 1 次（类型：OEM 查询）
    total_visits, today_visits, _ = do_count_once("oem_query")

    if not df_part.empty and search_text_oem.strip():
        line_count = check_limit(search_text_oem, 1000)
        if line_count > 1000:
            st.error(f"❌ 输入数据过多！当前 {line_count} 行，单次查询不得超过 1000 条。")
            st.stop()

        cleaned_queries = [
            clean_oem(line.strip())
            for line in search_text_oem.strip().split("\n")
            if line.strip()
        ]
        cleaned_queries = [q for q in cleaned_queries if q]

        if mode_oem == "精确匹配":
            # ===== 精确匹配：合并单元格展示 =====
            final_results = []
            for idx, q_oem in enumerate(cleaned_queries, 1):
                matches = oem_to_parts.get(q_oem, [])
                if matches:
                    unique_matches = list(set(matches))
                    final_results.append({
                        "序号": idx,
                        "查询OEM": q_oem,
                        "零件OEM": q_oem,
                        "结果零件编号": ",".join(unique_matches),
                        "匹配模式": "精准匹配",
                    })
                else:
                    final_results.append({
                        "序号": idx,
                        "查询OEM": q_oem,
                        "零件OEM": q_oem,
                        "结果零件编号": "未找到",
                        "匹配模式": "无",
                    })

            if final_results:
                df_results = pd.DataFrame(final_results)
                format_search_results(
                    df_results,
                    f"找到 {len([r for r in final_results if r['匹配模式'] != '无'])} 个有结果的查询",
                )
            else:
                st.warning("未找到任何结果。")

        else:
            # ===== 宽泛匹配：每个匹配结果单独一行 =====
            results = []
            idx = 1

            for q_oem in cleaned_queries:
                q_len = len(q_oem)

                candidate_dfs = []
                for length in [q_len - 1, q_len, q_len + 1]:
                    if length in len_groups:
                        candidate_dfs.append(len_groups[length])

                if not candidate_dfs:
                    results.append({
                        "序号": idx,
                        "查询OEM": q_oem,
                        "零件OEM": "未找到",
                        "结果零件编号": "未找到",
                        "匹配模式": "无",
                    })
                    idx += 1
                    continue

                candidates = pd.concat(candidate_dfs, ignore_index=True)

                exact_mask = candidates["OEM编号"] == q_oem
                exact_matches = candidates[exact_mask]
                fuzzy_candidates = candidates[~exact_mask]

                temp_results = []

                if not exact_matches.empty:
                    for _, row in exact_matches.iterrows():
                        temp_results.append({
                            "OEM编号": row["OEM编号"],
                            "零件编号": row["零件编号"],
                            "匹配模式": "精准匹配",
                        })

                if not fuzzy_candidates.empty:
                    contains_db = fuzzy_candidates["OEM编号"].str.contains(q_oem, regex=False, na=False)
                    contains_q = fuzzy_candidates["OEM编号"].apply(lambda x: x in q_oem)
                    fuzzy_mask = contains_db | contains_q
                    fuzzy_matches = fuzzy_candidates[fuzzy_mask]

                    if not fuzzy_matches.empty:
                        for _, row in fuzzy_matches.iterrows():
                            temp_results.append({
                                "OEM编号": row["OEM编号"],
                                "零件编号": row["零件编号"],
                                "匹配模式": "模糊匹配",
                            })

                if temp_results:
                    seen = set()
                    for item in temp_results:
                        key = (item["OEM编号"], item["零件编号"])
                        if key not in seen:
                            results.append({
                                "序号": idx,
                                "查询OEM": q_oem,
                                "零件OEM": item["OEM编号"],
                                "结果零件编号": item["零件编号"],
                                "匹配模式": item["匹配模式"],
                            })
                            seen.add(key)
                    idx += 1
                else:
                    results.append({
                        "序号": idx,
                        "查询OEM": q_oem,
                        "零件OEM": "未找到",
                        "结果零件编号": "未找到",
                        "匹配模式": "无",
                    })
                    idx += 1

            if results:
                df_results = pd.DataFrame(results)
                format_search_results(df_results)
            else:
                st.warning("未找到任何结果。")

        elapsed_time = time.time() - start_time
        st.caption(f"⚡ 查询耗时：{elapsed_time:.3f} 秒")

    elif df_part.empty:
        st.error("零件数据未加载，请检查 Parquet 文件。")
    else:
        st.warning("请输入 OEM 编号。")

# ==========================================
# 🧰 文本处理工具箱
# ==========================================
st.subheader("🧰 文本处理工具箱")
tab_multi_to_single, tab_single_to_multi = st.tabs(["🔄 多行转单行", "⬇️ 单行转多行"])

# --- 选项卡 1：多行转单行 ---
with tab_multi_to_single:
    st.markdown("将多行文本合并为一行，使用英文逗号 `,` 作为分隔符。")
    col_input_1, col_output_1 = st.columns([3, 1])
    with col_input_1:
        multi_line_input = st.text_area(
            "📝 输入多行数据",
            placeholder="支持批量输入，请换行分隔：\nTC1445\nTG1891\n(最多100行)",
            key="multi_line_input",
            height=150,
        )

    if st.button("➡️ 转换为单行", type="secondary", key="btn_multi_to_single"):
        # 登录账户计数：文本工具按钮点击同样计入（类型：多行转单行）
        do_count_once("multi_to_single")

        raw_text = multi_line_input.strip()
        if raw_text:
            all_lines = raw_text.split("\n")
            total_raw_lines = len(all_lines)
            if total_raw_lines > 100:
                st.error(f"❌ 输入行数过多！当前 {total_raw_lines} 行，单次转换不得超过 100 行。")
            else:
                valid_lines = [line.strip() for line in all_lines if line.strip()]
                if valid_lines:
                    result_line = ",".join(valid_lines)
                    st.text_area("✅ 转换结果", value=result_line, key="result_line_tab1", height=50)
                    st.success(f"转换成功！共处理 {len(valid_lines)} 个有效数据。")
                else:
                    st.warning("输入内容为空或没有有效数据行。")
        else:
            st.warning("请输入一些数据。")

# --- 选项卡 2：单行转多行 ---
with tab_single_to_multi:
    st.markdown("将用英文逗号 `,` 分隔的一行文本，拆分为多行显示。")
    col_input_2, col_output_2 = st.columns([3, 1])
    with col_input_2:
        single_line_input = st.text_area(
            "🔤 输入单行数据",
            placeholder="请在此输入用逗号分隔的数据，例如：\n38810,926003,TG1891",
            key="single_line_input",
            height=100,
        )

    if st.button("⬇️ 转换为多行", type="secondary", key="btn_single_to_multi"):
        # 登录账户计数：文本工具按钮点击同样计入（类型：单行转多行）
        do_count_once("single_to_multi")

        raw_text = single_line_input.strip()
        if raw_text:
            potential_parts = [part.strip() for part in raw_text.split(",")]
            total_parts = len(potential_parts)
            if total_parts > 1000:
                st.error(f"❌ 分割段数过多！当前检测到 {total_parts} 段，单次转换不得超过 1000 段。")
            else:
                valid_parts = [part for part in potential_parts if part]
                if valid_parts:
                    result_multi_line = "\n".join(valid_parts)
                    st.text_area("✅ 转换结果", value=result_multi_line, key="result_multi_line_tab2", height=200)
                    st.success(f"转换成功！共拆分出 {len(valid_parts)} 行有效数据。")
                else:
                    st.warning("输入内容为空或没有有效数据段。")
        else:
            st.warning("请输入一些数据。")

# 数据预览
with st.expander("查看原始数据预览"):
    if not df_part.empty:
        st.write("**零件 OEM 数据 (2.parquet):**")
        st.dataframe(df_part.head(5))
