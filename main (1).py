"""
==========================================================
ربات مدیریت گروه پیشرو - نسخه تک‌فایلی
==========================================================
همه‌چیز (تنظیمات، دیتابیس، دستورات، ضد اسپم) در همین یک فایل است
تا آپلود و مدیریت از گوشی راحت‌تر باشد.

نحوه اجرا: python main.py
نیازمندی‌ها: فایل requirements.txt
==========================================================
"""

import os
import re
import time
import logging
import sqlite3
from datetime import timedelta
from functools import wraps
from collections import defaultdict, deque
from contextlib import contextmanager
from dotenv import load_dotenv

from telegram import Update, ChatPermissions
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters


# ==========================================================
# بخش ۱: تنظیمات (Config)
# ==========================================================

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
OWNER_ID = int(os.getenv("OWNER_ID", "0"))

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN تنظیم نشده! آن را در Environment Variables وارد کنید.")
if not OWNER_ID:
    raise RuntimeError("OWNER_ID تنظیم نشده! آیدی عددی خودتان را در Environment Variables وارد کنید.")

PERMISSION_LEVELS = {"MODERATOR": 1, "ADMIN": 2, "SENIOR_ADMIN": 3}

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)


# ==========================================================
# بخش ۲: دیتابیس (Database)
# ==========================================================

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bot_data.db")


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            group_id INTEGER PRIMARY KEY,
            title TEXT,
            added_at TEXT,
            is_active INTEGER DEFAULT 1,
            antispam_enabled INTEGER DEFAULT 1,
            antilink_enabled INTEGER DEFAULT 1,
            welcome_enabled INTEGER DEFAULT 1,
            welcome_text TEXT DEFAULT 'به گروه خوش آمدید!',
            welcome_media_file_id TEXT,
            forced_join_channel TEXT,
            max_warns INTEGER DEFAULT 3
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS group_admins (
            group_id INTEGER, user_id INTEGER, permission_level INTEGER DEFAULT 1,
            added_by INTEGER, added_at TEXT, PRIMARY KEY (group_id, user_id)
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            group_id INTEGER, user_id INTEGER, username TEXT, first_name TEXT,
            message_count INTEGER DEFAULT 0, warn_count INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0, is_muted INTEGER DEFAULT 0,
            joined_at TEXT, last_active TEXT, PRIMARY KEY (group_id, user_id)
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS action_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER, actor_id INTEGER,
            actor_name TEXT, action TEXT, target_id INTEGER, target_name TEXT,
            reason TEXT, timestamp TEXT
        )""")
        conn.commit()


def add_group(group_id, title):
    with get_connection() as conn:
        conn.execute("INSERT OR IGNORE INTO groups (group_id, title, added_at) VALUES (?, ?, ?)",
                      (group_id, title, _now()))


def get_group_settings(group_id):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM groups WHERE group_id = ?", (group_id,)).fetchone()
        return dict(row) if row else None


def add_group_admin(group_id, user_id, level, added_by):
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO group_admins (group_id, user_id, permission_level, added_by, added_at) "
            "VALUES (?, ?, ?, ?, ?)", (group_id, user_id, level, added_by, _now()))


def remove_group_admin(group_id, user_id):
    with get_connection() as conn:
        conn.execute("DELETE FROM group_admins WHERE group_id = ? AND user_id = ?", (group_id, user_id))


def get_group_admin_level(group_id, user_id):
    with get_connection() as conn:
        row = conn.execute("SELECT permission_level FROM group_admins WHERE group_id = ? AND user_id = ?",
                            (group_id, user_id)).fetchone()
        return row["permission_level"] if row else 0


def upsert_user(group_id, user_id, username, first_name):
    with get_connection() as conn:
        existing = conn.execute("SELECT 1 FROM users WHERE group_id = ? AND user_id = ?",
                                 (group_id, user_id)).fetchone()
        now = _now()
        if existing:
            conn.execute(
                "UPDATE users SET username=?, first_name=?, message_count = message_count + 1, last_active=? "
                "WHERE group_id=? AND user_id=?", (username, first_name, now, group_id, user_id))
        else:
            conn.execute(
                "INSERT INTO users (group_id, user_id, username, first_name, message_count, joined_at, last_active) "
                "VALUES (?, ?, ?, ?, 1, ?, ?)", (group_id, user_id, username, first_name, now, now))


def increment_warn(group_id, user_id):
    with get_connection() as conn:
        conn.execute("UPDATE users SET warn_count = warn_count + 1 WHERE group_id = ? AND user_id = ?",
                      (group_id, user_id))
        row = conn.execute("SELECT warn_count FROM users WHERE group_id = ? AND user_id = ?",
                            (group_id, user_id)).fetchone()
        return row["warn_count"] if row else 0


def reset_warn(group_id, user_id):
    with get_connection() as conn:
        conn.execute("UPDATE users SET warn_count = 0 WHERE group_id = ? AND user_id = ?", (group_id, user_id))


def set_ban_status(group_id, user_id, banned):
    with get_connection() as conn:
        conn.execute("UPDATE users SET is_banned = ? WHERE group_id = ? AND user_id = ?",
                      (1 if banned else 0, group_id, user_id))


def get_group_stats(group_id):
    with get_connection() as conn:
        total_users = conn.execute("SELECT COUNT(*) as c FROM users WHERE group_id = ?",
                                    (group_id,)).fetchone()["c"]
        total_messages = conn.execute("SELECT SUM(message_count) as s FROM users WHERE group_id = ?",
                                       (group_id,)).fetchone()["s"] or 0
        banned_count = conn.execute("SELECT COUNT(*) as c FROM users WHERE group_id = ? AND is_banned = 1",
                                     (group_id,)).fetchone()["c"]
        top_users = conn.execute(
            "SELECT user_id, username, first_name, message_count FROM users "
            "WHERE group_id = ? ORDER BY message_count DESC LIMIT 5", (group_id,)).fetchall()
        return {"total_users": total_users, "total_messages": total_messages,
                "banned_count": banned_count, "top_users": [dict(u) for u in top_users]}


def log_action(group_id, actor_id, actor_name, action, target_id=None, target_name=None, reason=None):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO action_logs (group_id, actor_id, actor_name, action, target_id, target_name, reason, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (group_id, actor_id, actor_name, action, target_id, target_name, reason, _now()))


def get_recent_logs(group_id, limit=15):
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM action_logs WHERE group_id = ? ORDER BY id DESC LIMIT ?",
                             (group_id, limit)).fetchall()
        return [dict(r) for r in rows]


def _now():
    from datetime import datetime
    return datetime.utcnow().isoformat()


# ==========================================================
# بخش ۳: احراز هویت و سطوح دسترسی (Permissions)
# ==========================================================

def is_owner(user_id: int) -> bool:
    return user_id == OWNER_ID


def owner_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *a, **kw):
        user = update.effective_user
        if not user or not is_owner(user.id):
            if update.effective_message:
                await update.effective_message.reply_text("⛔️ این دستور فقط مخصوص مالک ربات است.")
            return
        return await func(update, context, *a, **kw)
    return wrapper


def requires_level(min_level: int):
    def decorator(func):
        @wraps(func)
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *a, **kw):
            user = update.effective_user
            chat = update.effective_chat
            if not user or not chat:
                return
            if is_owner(user.id):
                return await func(update, context, *a, **kw)
            level = get_group_admin_level(chat.id, user.id)
            if level < min_level:
                await update.effective_message.reply_text("⛔️ شما دسترسی کافی برای این دستور را ندارید.")
                return
            return await func(update, context, *a, **kw)
        return wrapper
    return decorator


# ==========================================================
# بخش ۴: ضد اسپم (Anti-Spam)
# ==========================================================

LINK_PATTERN = re.compile(r"(https?://\S+|t\.me/\S+|telegram\.me/\S+|@\w{4,32})", re.IGNORECASE)
_user_message_times = defaultdict(lambda: deque(maxlen=10))
FLOOD_MESSAGE_LIMIT = 6
FLOOD_TIME_WINDOW = 8

SUSPICIOUS_KEYWORDS = [
    "کلیک کن", "برنده شدید", "سود تضمینی", "دعوت با لینک زیر",
    "کسب درآمد", "سرمایه گذاری تضمینی", "واریز فوری"
]


def contains_link(text: str) -> bool:
    return bool(text) and bool(LINK_PATTERN.search(text))


def is_flooding(group_id: int, user_id: int) -> bool:
    key = (group_id, user_id)
    now = time.time()
    times = _user_message_times[key]
    times.append(now)
    while times and now - times[0] > FLOOD_TIME_WINDOW:
        times.popleft()
    return len(times) >= FLOOD_MESSAGE_LIMIT


def looks_suspicious(text: str) -> bool:
    if not text:
        return False
    return any(kw in text for kw in SUSPICIOUS_KEYWORDS)


# ==========================================================
# بخش ۵: دستورات عمومی (start, help, stats, welcome)
# ==========================================================

WELCOME_TEXT = (
    "🛡️ سلام! من ربات مدیریت گروه شما هستم.\n\n"
    "امکانات من:\n"
    "• ضد اسپم و ضد لینک هوشمند\n"
    "• سیستم اخطار / سکوت / اخراج / مسدودسازی\n"
    "• پنل مدیریت و سطوح دسترسی ادمین\n"
    "• آمار دقیق گروه و کاربران\n"
    "• لاگ کامل تمام اقدامات مدیریتی\n\n"
    "برای راهنما بنویسید: /help"
)

HELP_TEXT = (
    "📖 راهنمای دستورات\n\n"
    "🔹 دستورات عمومی:\n"
    "/start - شروع کار با ربات\n"
    "/help - نمایش این راهنما\n"
    "/stats - آمار گروه\n\n"
    "🔹 دستورات مدیریتی (نیاز به دسترسی، با ریپلای روی پیام کاربر):\n"
    "/warn [دلیل] - اخطار به کاربر\n"
    "/unwarn - پاک کردن اخطارها\n"
    "/mute [دقیقه] - سکوت کاربر\n"
    "/unmute - رفع سکوت\n"
    "/kick [دلیل] - اخراج کاربر\n"
    "/ban [دلیل] - مسدودسازی کاربر\n"
    "/unban [آیدی عددی] - رفع مسدودیت\n\n"
    "🔹 دستورات مخصوص مالک:\n"
    "/setadmin [1-3] - تعیین ادمین داخلی (ریپلای کنید)\n"
    "/removeadmin - حذف ادمین داخلی (ریپلای کنید)\n"
    "/logs - نمایش لاگ فعالیت‌ها"
)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if chat.type in ("group", "supergroup"):
        add_group(chat.id, chat.title)
    await update.effective_message.reply_text(WELCOME_TEXT)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(HELP_TEXT)


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if chat.type not in ("group", "supergroup"):
        await update.effective_message.reply_text("این دستور فقط در گروه کار می‌کند.")
        return
    stats = get_group_stats(chat.id)
    lines = [
        "📊 آمار گروه\n",
        f"👥 تعداد کاربران فعال: {stats['total_users']}",
        f"💬 مجموع پیام‌ها: {stats['total_messages']}",
        f"🚫 تعداد مسدودشده‌ها: {stats['banned_count']}\n",
        "🏆 فعال‌ترین اعضا:"
    ]
    for i, u in enumerate(stats["top_users"], 1):
        name = u["first_name"] or u["username"] or str(u["user_id"])
        lines.append(f"{i}. {name} — {u['message_count']} پیام")
    await update.effective_message.reply_text("\n".join(lines))


async def welcome_new_members(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    group = get_group_settings(chat.id)
    if not group or not group.get("welcome_enabled"):
        return
    welcome_text = group.get("welcome_text") or "به گروه خوش آمدید!"
    media_file_id = group.get("welcome_media_file_id")
    for member in update.effective_message.new_chat_members:
        if member.is_bot:
            continue
        text = f"👋 {member.full_name} عزیز، {welcome_text}"
        try:
            if media_file_id:
                await context.bot.send_photo(chat.id, media_file_id, caption=text)
            else:
                await update.effective_message.reply_text(text)
        except Exception:
            await update.effective_message.reply_text(text)


# ==========================================================
# بخش ۶: دستورات مدیریتی (warn, mute, kick, ban)
# ==========================================================

def _get_target_user(update: Update):
    msg = update.effective_message
    if msg.reply_to_message and msg.reply_to_message.from_user:
        return msg.reply_to_message.from_user
    return None


def _get_reason(context: ContextTypes.DEFAULT_TYPE) -> str:
    return " ".join(context.args) if context.args else "دلیلی ذکر نشده"


@requires_level(PERMISSION_LEVELS["MODERATOR"])
async def warn_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text("⚠️ روی پیام کاربر ریپلای کنید و بنویسید /warn [دلیل]")
        return
    chat_id = update.effective_chat.id
    reason = _get_reason(context)
    actor = update.effective_user
    warn_count = increment_warn(chat_id, target.id)
    group = get_group_settings(chat_id)
    max_warns = group["max_warns"] if group else 3
    log_action(chat_id, actor.id, actor.full_name, "warn", target.id, target.full_name, reason)
    if warn_count >= max_warns:
        try:
            await context.bot.ban_chat_member(chat_id, target.id)
            set_ban_status(chat_id, target.id, True)
            log_action(chat_id, actor.id, actor.full_name, "auto_ban_after_warns", target.id, target.full_name,
                       f"{max_warns} اخطار دریافت کرد")
            await update.effective_message.reply_text(
                f"🚫 {target.full_name} پس از دریافت {max_warns} اخطار، از گروه مسدود شد.")
        except Exception as e:
            await update.effective_message.reply_text(f"خطا در مسدودسازی: {e}")
    else:
        await update.effective_message.reply_text(
            f"⚠️ اخطار به {target.full_name} داده شد.\nدلیل: {reason}\nتعداد اخطارها: {warn_count}/{max_warns}")


@requires_level(PERMISSION_LEVELS["MODERATOR"])
async def unwarn_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text("⚠️ روی پیام کاربر ریپلای کنید و بنویسید /unwarn")
        return
    reset_warn(update.effective_chat.id, target.id)
    await update.effective_message.reply_text(f"✅ اخطارهای {target.full_name} پاک شد.")


@requires_level(PERMISSION_LEVELS["ADMIN"])
async def mute_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text("⚠️ روی پیام کاربر ریپلای کنید و بنویسید /mute [مدت به دقیقه]")
        return
    chat_id = update.effective_chat.id
    actor = update.effective_user
    reason = _get_reason(context)
    minutes = int(context.args[0]) if context.args and context.args[0].isdigit() else 0
    until_date = update.effective_message.date + timedelta(minutes=minutes) if minutes > 0 else None
    try:
        await context.bot.restrict_chat_member(
            chat_id, target.id, permissions=ChatPermissions(can_send_messages=False), until_date=until_date)
        log_action(chat_id, actor.id, actor.full_name, "mute", target.id, target.full_name, reason)
        duration_text = f"{minutes} دقیقه" if minutes > 0 else "نامحدود"
        await update.effective_message.reply_text(
            f"🔇 {target.full_name} سکوت شد.\nمدت: {duration_text}\nدلیل: {reason}")
    except Exception as e:
        await update.effective_message.reply_text(f"خطا: {e}")


@requires_level(PERMISSION_LEVELS["ADMIN"])
async def unmute_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text("⚠️ روی پیام کاربر ریپلای کنید و بنویسید /unmute")
        return
    chat_id = update.effective_chat.id
    try:
        await context.bot.restrict_chat_member(
            chat_id, target.id,
            permissions=ChatPermissions(can_send_messages=True, can_send_audios=True, can_send_documents=True,
                                         can_send_photos=True, can_send_videos=True, can_send_other_messages=True))
        await update.effective_message.reply_text(f"🔊 سکوت {target.full_name} برداشته شد.")
    except Exception as e:
        await update.effective_message.reply_text(f"خطا: {e}")


@requires_level(PERMISSION_LEVELS["ADMIN"])
async def kick_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text("⚠️ روی پیام کاربر ریپلای کنید و بنویسید /kick [دلیل]")
        return
    chat_id = update.effective_chat.id
    actor = update.effective_user
    reason = _get_reason(context)
    try:
        await context.bot.unban_chat_member(chat_id, target.id)
        log_action(chat_id, actor.id, actor.full_name, "kick", target.id, target.full_name, reason)
        await update.effective_message.reply_text(f"👢 {target.full_name} از گروه اخراج شد.\nدلیل: {reason}")
    except Exception as e:
        await update.effective_message.reply_text(f"خطا: {e}")


@requires_level(PERMISSION_LEVELS["ADMIN"])
async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = _get_target_user(update)
    if not target:
        await update.effective_message.reply_text("⚠️ روی پیام کاربر ریپلای کنید و بنویسید /ban [دلیل]")
        return
    chat_id = update.effective_chat.id
    actor = update.effective_user
    reason = _get_reason(context)
    try:
        await context.bot.ban_chat_member(chat_id, target.id)
        set_ban_status(chat_id, target.id, True)
        log_action(chat_id, actor.id, actor.full_name, "ban", target.id, target.full_name, reason)
        await update.effective_message.reply_text(f"🚫 {target.full_name} مسدود شد.\nدلیل: {reason}")
    except Exception as e:
        await update.effective_message.reply_text(f"خطا: {e}")


@requires_level(PERMISSION_LEVELS["ADMIN"])
async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.effective_message.reply_text("⚠️ آیدی عددی کاربر را بنویسید: /unban [user_id]")
        return
    chat_id = update.effective_chat.id
    try:
        user_id = int(context.args[0])
        await context.bot.unban_chat_member(chat_id, user_id, only_if_banned=True)
        set_ban_status(chat_id, user_id, False)
        await update.effective_message.reply_text(f"✅ کاربر {user_id} از مسدودیت خارج شد.")
    except Exception as e:
        await update.effective_message.reply_text(f"خطا: {e}")


# ==========================================================
# بخش ۷: پنل مالک (Owner Panel)
# ==========================================================

@owner_only
async def set_admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg.reply_to_message:
        await msg.reply_text(
            "⚠️ روی پیام کاربر ریپلای کنید و بنویسید:\n"
            "/setadmin 1  (ناظر)\n/setadmin 2  (ادمین)\n/setadmin 3  (ادمین ارشد)")
        return
    if not context.args or not context.args[0].isdigit():
        await msg.reply_text("⚠️ سطح دسترسی را وارد کنید (1 تا 3).")
        return
    level = int(context.args[0])
    if level not in (1, 2, 3):
        await msg.reply_text("⚠️ سطح دسترسی باید 1، 2 یا 3 باشد.")
        return
    target = msg.reply_to_message.from_user
    chat_id = update.effective_chat.id
    add_group_admin(chat_id, target.id, level, update.effective_user.id)
    log_action(chat_id, update.effective_user.id, update.effective_user.full_name,
               "set_admin", target.id, target.full_name, f"سطح {level}")
    level_names = {1: "ناظر", 2: "ادمین", 3: "ادمین ارشد"}
    await msg.reply_text(f"✅ {target.full_name} به عنوان «{level_names[level]}» تعیین شد.")


@owner_only
async def remove_admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg.reply_to_message:
        await msg.reply_text("⚠️ روی پیام کاربر ریپلای کنید و بنویسید /removeadmin")
        return
    target = msg.reply_to_message.from_user
    chat_id = update.effective_chat.id
    remove_group_admin(chat_id, target.id)
    log_action(chat_id, update.effective_user.id, update.effective_user.full_name,
               "remove_admin", target.id, target.full_name, None)
    await msg.reply_text(f"✅ دسترسی ادمین {target.full_name} حذف شد.")


@owner_only
async def logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    logs = get_recent_logs(chat_id, limit=15)
    if not logs:
        await update.effective_message.reply_text("📋 هنوز هیچ اقدامی ثبت نشده است.")
        return
    action_names = {
        "warn": "⚠️ اخطار", "mute": "🔇 سکوت", "kick": "👢 اخراج",
        "ban": "🚫 مسدودسازی", "auto_ban_after_warns": "🚫 مسدودسازی خودکار",
        "set_admin": "👤 تعیین ادمین", "remove_admin": "❌ حذف ادمین"
    }
    lines = ["📋 آخرین فعالیت‌های گروه:\n"]
    for log in logs:
        label = action_names.get(log["action"], log["action"])
        line = f"{label} | توسط: {log['actor_name']}"
        if log["target_name"]:
            line += f" | هدف: {log['target_name']}"
        if log["reason"]:
            line += f" | دلیل: {log['reason']}"
        lines.append(line)
    await update.effective_message.reply_text("\n".join(lines))


# ==========================================================
# بخش ۸: ردیابی پیام‌ها و اجرای ضد اسپم (Message Tracker)
# ==========================================================

async def track_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if not msg or not user or chat.type not in ("group", "supergroup"):
        return
    if user.is_bot:
        return

    group = get_group_settings(chat.id)
    if not group:
        add_group(chat.id, chat.title)
        group = get_group_settings(chat.id)

    upsert_user(chat.id, user.id, user.username, user.first_name)

    if is_owner(user.id):
        return

    try:
        member = await context.bot.get_chat_member(chat.id, user.id)
        if member.status in ("administrator", "creator"):
            return
    except Exception:
        pass

    text = msg.text or msg.caption or ""

    if is_flooding(chat.id, user.id):
        try:
            await msg.delete()
            log_action(chat.id, user.id, user.full_name, "auto_delete_flood", user.id, user.full_name,
                       "ارسال پیام بیش از حد مجاز در زمان کوتاه")
        except Exception:
            pass
        return

    if group.get("antilink_enabled") and contains_link(text):
        try:
            await msg.delete()
            log_action(chat.id, user.id, user.full_name, "auto_delete_link", user.id, user.full_name,
                       "ارسال لینک/تبلیغ غیرمجاز")
        except Exception:
            pass
        return

    if group.get("antispam_enabled") and looks_suspicious(text):
        try:
            await msg.delete()
            log_action(chat.id, user.id, user.full_name, "auto_delete_spam", user.id, user.full_name,
                       "محتوای مشکوک به اسپم")
        except Exception:
            pass
        return


# ==========================================================
# بخش ۹: اجرای اصلی ربات (Main)
# ==========================================================

def main():
    logger.info("در حال راه‌اندازی دیتابیس...")
    init_db()

    logger.info("در حال ساخت ربات...")
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("stats", stats_command))

    app.add_handler(CommandHandler("warn", warn_command))
    app.add_handler(CommandHandler("unwarn", unwarn_command))
    app.add_handler(CommandHandler("mute", mute_command))
    app.add_handler(CommandHandler("unmute", unmute_command))
    app.add_handler(CommandHandler("kick", kick_command))
    app.add_handler(CommandHandler("ban", ban_command))
    app.add_handler(CommandHandler("unban", unban_command))

    app.add_handler(CommandHandler("setadmin", set_admin_command))
    app.add_handler(CommandHandler("removeadmin", remove_admin_command))
    app.add_handler(CommandHandler("logs", logs_command))

    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, welcome_new_members))
    app.add_handler(MessageHandler(
        filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND, track_message))

    logger.info("ربات با موفقیت روشن شد. در حال گوش دادن به پیام‌ها...")
    app.run_polling(allowed_updates=["message", "chat_member"])


if __name__ == "__main__":
    main()
