import sys, os, json, hashlib, tempfile, psutil, time, ctypes, ctypes.wintypes, math, subprocess
from datetime import timedelta
from enum import Enum

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QStackedWidget, QProgressBar, QSizePolicy,
    QGraphicsBlurEffect, QMenu, QComboBox, QSpinBox, QCheckBox, QSlider,
    QColorDialog, QScrollArea, QLineEdit
)
from PyQt6.QtCore  import (
    Qt, QThread, pyqtSignal, QRect, QTimer, QPoint, QSize, QRectF,
    QPropertyAnimation, QEasingCurve, QVariantAnimation, QSequentialAnimationGroup,
    QParallelAnimationGroup, QObject, QEvent
)
from PyQt6.QtGui   import (
    QFont, QFontDatabase, QColor, QPainter, QPen, QBrush, QLinearGradient,
    QRadialGradient, QPixmap, QPainterPath, QIcon, QImage, QFontMetrics,
    QCursor
)


# ═══════════════════════════════════════════════════════════════════
#  APP SETTINGS  (хранится рядом со скриптом, переживает перезапуск)
# ═══════════════════════════════════════════════════════════════════
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zeus_settings.json")

DEFAULT_SETTINGS = {
    "lang": "ru",
    "accent_color": "#d9c7a8",   # цвет программы
    "bg_tint_color": "#191412",  # цвет затемнения фонового изображения
    "glow_color": "#d9c7a8",     # цвет мерцания (звёзды Dynamic Island)
    "licensed": False,
    "saved_key": "",
    "remember_key": False,
    "last_valid_at": 0,
}

def load_app_settings():
    cfg = dict(DEFAULT_SETTINGS)
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
    except Exception:
        pass
    return cfg

def save_app_settings(updates: dict):
    cfg = load_app_settings()
    cfg.update(updates)
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return cfg

APP_SETTINGS = load_app_settings()


def _hex_to_rgb(hex_color, fallback=(217, 199, 168)):
    try:
        hc = hex_color.lstrip("#")
        if len(hc) == 3:
            hc = "".join(c * 2 for c in hc)
        return tuple(int(hc[i:i + 2], 16) for i in (0, 2, 4))
    except Exception:
        return fallback

def _rgb_to_hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*[max(0, min(255, int(c))) for c in rgb[:3]])

def _shade(hex_color, factor):
    """factor > 1.0 = светлее, < 1.0 = темнее"""
    r, g, b = _hex_to_rgb(hex_color)
    if factor >= 1.0:
        r = r + (255 - r) * (factor - 1.0)
        g = g + (255 - g) * (factor - 1.0)
        b = b + (255 - b) * (factor - 1.0)
    else:
        r, g, b = r * factor, g * factor, b * factor
    return _rgb_to_hex((r, g, b))


# ═══════════════════════════════════════════════════════════════════
#  KEY SYSTEM
#
#  Если KEY_SERVER_URL задан — ключ проверяется через сервер
#  (key_server.py из комплекта): сервер привязывает ключ к HWID этого
#  ПК, может отозвать ключ, ограничить срок действия и число активаций.
#  Если сервер недоступен (нет интернета), используется офлайн-грейс:
#  последняя успешная проверка кэшируется в zeus_settings.json и
#  считается валидной ещё OFFLINE_GRACE_DAYS дней.
#
#  Если KEY_SERVER_URL пустой — работает чисто офлайн-режим: ключ
#  валиден, если есть в VALID_KEYS или проходит контрольную сумму
#  (для тестов/демо-сборок без сервера).
# ═══════════════════════════════════════════════════════════════════
import urllib.request
import urllib.error
import uuid
import platform

KEY_SERVER_URL = "http://127.0.0.1:8080"   # например: "https://license.your-domain.com"
OFFLINE_GRACE_DAYS = 3
REQUEST_TIMEOUT = 6   # секунд

VALID_KEYS = {
    "ZEUS1-MIDNI-GHT00-DEMO1",
    "ZEUS1-MIDNI-GHT00-DEMO2",
}

KEY_SALT = "zeus-midnight-v2"


def _key_checksum_ok(key: str) -> bool:
    """Офлайн-алгоритм (используется только если KEY_SERVER_URL пуст):
    последняя группа — первые 5 символов SHA-256(остальной ключ + соль)."""
    parts = key.strip().upper().split("-")
    if len(parts) != 4 or any(len(p) != 5 for p in parts):
        return False
    body = "-".join(parts[:3])
    digest = hashlib.sha256((body + KEY_SALT).encode("utf-8")).hexdigest().upper()
    return digest[:5] == parts[3]


def get_hwid() -> str:
    """Стабильный идентификатор этого ПК (не привязан к личным данным —
    просто хэш от MAC-адреса и имени машины)."""
    raw = f"{uuid.getnode()}-{platform.node()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _server_request(path: str, payload: dict):
    """POST JSON на сервер ключей. Возвращает (ok, data_or_error_reason)."""
    url = KEY_SERVER_URL.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return True, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode("utf-8")).get("detail", str(e))
        except Exception:
            detail = str(e)
        return False, detail
    except Exception as e:
        return False, f"network_error: {e}"


def validate_key(key: str) -> bool:
    """Главная точка входа — используется и в KeyGateWindow, и при
    автологине по сохранённому ключу."""
    if not key:
        return False
    key = key.strip().upper()

    if not KEY_SERVER_URL:
        # Чисто офлайн-режим (без сервера)
        return key in VALID_KEYS or _key_checksum_ok(key)

    hwid = get_hwid()
    ok, result = _server_request("/activate", {"key": key, "hwid": hwid})
    if ok:
        save_app_settings({"last_valid_at": int(time.time())})
        return True

    # Сервер ответил, но отказал (ключ невалиден/отозван/чужой HWID) —
    # это не сетевая ошибка, грейс-период тут не положен.
    if not str(result).startswith("network_error"):
        return False

    # Сервер недоступен — даём поработать по последней удачной проверке,
    # если она была не более OFFLINE_GRACE_DAYS дней назад.
    last_valid_at = APP_SETTINGS.get("last_valid_at", 0)
    if last_valid_at and (time.time() - last_valid_at) < OFFLINE_GRACE_DAYS * 86400:
        return True
    return False


# ═══════════════════════════════════════════════════════════════════
#  TRANSLATIONS
# ═══════════════════════════════════════════════════════════════════
TRANSLATIONS = {
    "ru": {
        "welcome": "Добро пожаловать,",
        "optimize_slogan": "Оптимизируй свой\nПК в один клик",
        "optimize_desc": "Держи систему быстрой, стабильной и чистой.",
        "optimize_btn": "ОПТИМИЗИРОВАТЬ",
        "system_status": "СТАТУС СИСТЕМЫ",
        "excellent": "Отлично",
        "good": "Хорошо",
        "load": "Нагрузка",
        "quick_actions": "Быстрые действия",
        "cleanup": "Очистка мусора",
        "cleanup_desc": "Удалить лишние файлы\nи освободить место.",
        "cleanup_btn": "СКАНИРОВАТЬ",
        "boost": "Буст производительности",
        "boost_desc": "Оптимизировать систему\nдля скорости.",
        "boost_btn": "БУСТ",
        "privacy": "Конфиденциальность",
        "privacy_desc": "Очистить следы\nи защитить данные.",
        "privacy_btn": "ОЧИСТИТЬ",
        "gaming": "Игровой режим",
        "gaming_desc": "Оптимизировать ПК\nдля игр.",
        "gaming_btn": "ВКЛЮЧИТЬ",
        "gaming_off_btn": "ВЫКЛ",
        "system_info": "Обзор системы",
        "os_label": "ОС",
        "uptime_label": "Аптайм",
        "processes_label": "Процессы",
        "storage": "Хранилище",
        "performance_monitor": "Мониторинг производительности",
        "cpu_label": "Процессор",
        "memory_label": "Память",
        "disk_label": "Диск",
        "cores": "Ядра CPU",
        "ram_used": "RAM занято",
        "ram_free": "RAM свободно",
        "disk_used": "Диск занят",
        "fps_label": "FPS",
        "ping_label": "PING",
        "music_label": "Музыка",
        "dynamic_island": "Dynamic Island",
        "crosshair": "Прицел",
        "crosshair_color": "Цвет прицела",
        "crosshair_animation": "Анимация прицела",
        "island_animation": "Анимация Island",
        "island_size": "Размер Island",
        "island_width": "Ширина Island",
        "previous_track": "Предыдущая",
        "play_pause": "Play/Pause",
        "next_track": "Следующая",
        "island_enabled": "Island включен",
        "crosshair_enabled": "Прицел включен",
        "show_fps": "Показывать FPS",
        "show_ping": "Показывать PING",
        "show_music": "Показывать музыку",
        "settings": "Настройки",
        "pro_features": "Pro Функции",
        "dashboard": "Дашборд",
        "cleanup_page": "Очистка",
        "performance": "Производительность",
        "privacy_page": "Конфиденциальность",
        "tools": "Инструменты",
        "tools_title": "Системные твики",
        "tools_desc": "Точечные переключатели. Каждый можно включать и выключать отдельно — изменения применяются и откатываются по требованию.",
        "tool_core_parking": "Отключить CPU Core Parking",
        "tool_core_parking_desc": "Убирает задержку пробуждения «заснувших» ядер процессора при резкой нагрузке (например, в играх). Не влияет на температуру или износ.",
        "tool_usb_polling": "Снизить задержку USB-устройств",
        "tool_usb_polling_desc": "Отключает USB Selective Suspend — убирает программное усыпление USB-контроллера. Не меняет частоту опроса, заданную прошивкой устройства.",
        "tool_game_bar": "Отключить Xbox Game Bar",
        "tool_game_bar_desc": "Отключает оверлей записи игр Windows (GameDVR), который может создавать фоновую нагрузку.",
        "tool_process_priority": "Высокий приоритет Zeus Midnight",
        "tool_process_priority_desc": "Повышает приоритет процесса этого приложения. Действует только на сам Zeus Midnight, не на игры.",
        "about": "О программе",
        "version": "Zeus Midnight v2.2",
        "section_dev": "Раздел в разработке",
        "status_on": "Активен",
        "status_off": "Выключен",
        "appearance": "Внешний вид",
        "appearance_desc": "Настройте цветовую схему программы под себя.",
        "accent_color": "Цвет программы",
        "accent_color_desc": "Основной акцентный цвет кнопок, ползунков и подсветки интерфейса.",
        "bg_tint_color": "Цвет фона",
        "bg_tint_color_desc": "Цвет затемнения фоновой картинки (offset.png).",
        "glow_color": "Цвет мерцания",
        "glow_color_desc": "Цвет мерцающих звёзд и свечения Dynamic Island.",
        "pick_color": "Выбрать цвет",
        "reset_colors": "Сбросить",
        "apply_restart": "ПРИМЕНИТЬ И ПЕРЕЗАПУСТИТЬ",
        "restart_notice": "Изменения цвета применяются после перезапуска программы.",
        "key_title": "ZEUS MIDNIGHT",
        "key_subtitle": "Введите ключ доступа, чтобы продолжить",
        "key_placeholder": "XXXXX-XXXXX-XXXXX-XXXXX",
        "key_submit": "ВОЙТИ",
        "key_checking": "ПРОВЕРКА...",
        "key_invalid": "Неверный или истёкший ключ",
        "key_empty": "Введите ключ",
        "key_remember": "Запомнить на этом устройстве",
        "key_footer": "Нет ключа? Обратитесь к продавцу.",
        "key_welcome_back": "С возвращением",
    },
    "en": {
        "welcome": "Welcome,",
        "optimize_slogan": "Optimize Your\nPC in One Click",
        "optimize_desc": "Keep your system fast, stable and clean.",
        "optimize_btn": "OPTIMIZE",
        "system_status": "SYSTEM STATUS",
        "excellent": "Excellent",
        "good": "Good",
        "load": "Load",
        "quick_actions": "Quick Actions",
        "cleanup": "Cleanup",
        "cleanup_desc": "Remove unnecessary files\nand free up space.",
        "cleanup_btn": "SCAN",
        "boost": "Boost Performance",
        "boost_desc": "Optimize system\nfor speed.",
        "boost_btn": "BOOST",
        "privacy": "Privacy",
        "privacy_desc": "Clear traces\nand protect data.",
        "privacy_btn": "CLEAN",
        "gaming": "Gaming Mode",
        "gaming_desc": "Optimize PC\nfor gaming.",
        "gaming_btn": "ENABLE",
        "gaming_off_btn": "OFF",
        "system_info": "System Overview",
        "os_label": "OS",
        "uptime_label": "Uptime",
        "processes_label": "Processes",
        "storage": "Storage",
        "performance_monitor": "Performance Monitor",
        "cpu_label": "CPU",
        "memory_label": "Memory",
        "disk_label": "Disk",
        "cores": "CPU Cores",
        "ram_used": "RAM Used",
        "ram_free": "RAM Free",
        "disk_used": "Disk Used",
        "fps_label": "FPS",
        "ping_label": "PING",
        "music_label": "Music",
        "dynamic_island": "Dynamic Island",
        "crosshair": "Crosshair",
        "crosshair_color": "Crosshair Color",
        "crosshair_animation": "Crosshair Animation",
        "island_animation": "Island Animation",
        "island_size": "Island Size",
        "island_width": "Island Width",
        "previous_track": "Previous",
        "play_pause": "Play/Pause",
        "next_track": "Next",
        "island_enabled": "Island Enabled",
        "crosshair_enabled": "Crosshair Enabled",
        "show_fps": "Show FPS",
        "show_ping": "Show PING",
        "show_music": "Show Music",
        "settings": "Settings",
        "pro_features": "Pro Features",
        "dashboard": "Dashboard",
        "cleanup_page": "Cleanup",
        "performance": "Performance",
        "privacy_page": "Privacy",
        "tools": "Tools",
        "tools_title": "System Tweaks",
        "tools_desc": "Individual toggles. Each can be switched on and off independently — changes are applied and reverted on demand.",
        "tool_core_parking": "Disable CPU Core Parking",
        "tool_core_parking_desc": "Removes the wake-up delay of \"parked\" CPU cores under sudden load (e.g. in games). Does not affect temperature or wear.",
        "tool_usb_polling": "Reduce USB device latency",
        "tool_usb_polling_desc": "Disables USB Selective Suspend — removes software sleep of the USB controller. Does not change the polling rate set by the device firmware.",
        "tool_game_bar": "Disable Xbox Game Bar",
        "tool_game_bar_desc": "Disables the Windows game recording overlay (GameDVR), which can create background load.",
        "tool_process_priority": "High priority for Zeus Midnight",
        "tool_process_priority_desc": "Raises this app's own process priority. Only affects Zeus Midnight, not games.",
        "about": "About",
        "version": "Zeus Midnight v2.2",
        "section_dev": "Section Under Development",
        "status_on": "Active",
        "status_off": "Off",
        "appearance": "Appearance",
        "appearance_desc": "Customize the program's color scheme.",
        "accent_color": "Program Color",
        "accent_color_desc": "Main accent color for buttons, sliders and interface highlights.",
        "bg_tint_color": "Background Color",
        "bg_tint_color_desc": "Darkening tint color for the background image (offset.png).",
        "glow_color": "Flicker Color",
        "glow_color_desc": "Color of the twinkling stars and Dynamic Island glow.",
        "pick_color": "Pick Color",
        "reset_colors": "Reset",
        "apply_restart": "APPLY & RESTART",
        "restart_notice": "Color changes apply after the app restarts.",
        "key_title": "ZEUS MIDNIGHT",
        "key_subtitle": "Enter your access key to continue",
        "key_placeholder": "XXXXX-XXXXX-XXXXX-XXXXX",
        "key_submit": "UNLOCK",
        "key_checking": "CHECKING...",
        "key_invalid": "Invalid or expired key",
        "key_empty": "Enter a key",
        "key_remember": "Remember on this device",
        "key_footer": "Don't have a key? Contact the seller.",
        "key_welcome_back": "Welcome back",
    }
}

CURRENT_LANGUAGE = APP_SETTINGS.get("lang", "ru")

def t(key):
    return TRANSLATIONS.get(CURRENT_LANGUAGE, TRANSLATIONS["ru"]).get(key, key)

# ═══════════════════════════════════════════════════════════════════
#  PALETTE - НАСТРАИВАЕМАЯ ТЕМА
#  Базовые цвета берутся из zeus_settings.json (см. APP_SETTINGS выше).
#  Изменить их можно в Настройках → Внешний вид; программа перезапу-
#  скается, чтобы пересобрать все стили с новыми цветами.
# ═══════════════════════════════════════════════════════════════════
ACCENT   = APP_SETTINGS.get("accent_color", "#d9c7a8")   # Цвет программы
ACCENT2  = _shade(ACCENT, 0.92)                            # Чуть темнее
ACCENT3  = _shade(ACCENT, 0.82)                            # Ещё темнее
TEXT_PRI = "#f5f1ed"      # Very light beige
TEXT_MUT = "#8b8680"      # Muted beige-brown
TEXT_DIM = "#4a4844"      # Dark beige
SUCCESS  = "#4ade80"
WARNING  = "#f59e0b"
DANGER   = "#f87171"

ACCENT_RGB   = _hex_to_rgb(ACCENT)
ACCENT_A30   = ACCENT_RGB + (77,)

GLOW_COLOR = APP_SETTINGS.get("glow_color", "#d9c7a8")    # Цвет мерцания
GLOW_RGB   = _hex_to_rgb(GLOW_COLOR)

BG_TINT_COLOR = APP_SETTINGS.get("bg_tint_color", "#191412")  # Цвет фона
BG_TINT_RGB   = _hex_to_rgb(BG_TINT_COLOR)

CARD_TINT    = (25, 22, 20, 155)       # Тёмный бежевый
SIDEBAR_TINT = (20, 18, 16, 195)       # Более тёмный бежевый

BTN_GRAY        = ACCENT_RGB
BTN_FILL        = ACCENT_RGB + (20,)
BTN_FILL_HOVER  = ACCENT_RGB + (40,)
BTN_FILL_PRESS  = ACCENT_RGB + (10,)
BTN_BORDER      = ACCENT_RGB + (80,)

FONT_FAMILY = "Segoe UI Variable Display"

def _font(size, weight=QFont.Weight.Normal, family=None):
    f = QFont(family or FONT_FAMILY, size, weight)
    f.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
    return f


# ═══════════════════════════════════════════════════════════════════
#  BACKGROUND WIDGET
# ═══════════════════════════════════════════════════════════════════
class BackgroundWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._bg = None
        bg_paths = ["fon.png", "offset.png", "background.png", "bg.png"]
        for p in bg_paths:
            if os.path.exists(p):
                self._bg = QPixmap(p)
                break

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        w, h = self.width(), self.height()
        tr, tg_, tb = BG_TINT_RGB

        if self._bg and not self._bg.isNull():
            scaled = self._bg.scaled(self.size(),
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation)
            ox = (scaled.width() - w) // 2
            oy = (scaled.height() - h) // 2
            p.drawPixmap(0, 0, scaled, ox, oy, w, h)

            vg = QLinearGradient(0, 0, w, 0)
            vg.setColorAt(0.0, QColor(tr, tg_, tb, 240))
            vg.setColorAt(0.18, QColor(tr, tg_, tb, 190))
            vg.setColorAt(0.45, QColor(tr, tg_, tb, 130))
            vg.setColorAt(0.75, QColor(tr, tg_, tb,  90))
            vg.setColorAt(1.0,  QColor(tr, tg_, tb, 110))
            p.fillRect(0, 0, w, h, vg)

            tg = QLinearGradient(0, 0, 0, h)
            tg.setColorAt(0.0,  QColor(tr, tg_, tb, 70))
            tg.setColorAt(0.35, QColor(tr, tg_, tb,  0))
            tg.setColorAt(1.0,  QColor(tr, tg_, tb, 100))
            p.fillRect(0, 0, w, h, tg)
        else:
            p.fillRect(0, 0, w, h, QColor(tr, tg_, tb))


# ═══════════════════════════════════════════════════════════════════
#  DYNAMIC ISLAND WIDGET  — полностью переработан
# ═══════════════════════════════════════════════════════════════════
class DynamicIsland(QWidget):
    # базовые размеры (без scale)
    BASE_W = 340
    BASE_H_FULL = 110   # с музыкой
    BASE_H_MINI = 72    # без музыки

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMouseTracking(True)

        self._dragging  = False
        self._drag_pos  = None
        self._fps       = 0
        self._ping      = 0
        self._music     = "No Music"
        self._anim_en   = True
        self._scale     = 1.0
        self._tick      = 0           # master counter
        self._zeus_alpha = 0.0        # 0..1 breathe
        self._music_expanded = True   # свёрнута ли музыка
        self._show_fps  = True
        self._show_ping = True
        self._show_music = True
        self._visible   = True

        # звёзды: (rel_x, rel_y, phase, size_base)
        import random; random.seed(42)
        self._stars = [(random.uniform(0.1, 0.9),
                        random.uniform(0.15, 0.85),
                        random.uniform(0, 360),
                        random.uniform(1.5, 3.5)) for _ in range(18)]

        self._reposition()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick_fn)
        self._timer.start(16)

    # ── helpers ────────────────────────────────────────────────────
    def _base_h(self):
        return self.BASE_H_FULL if (self._music_expanded and self._show_music) else self.BASE_H_MINI

    def _reposition(self):
        sw = QApplication.primaryScreen().geometry().width()
        w = int(self.BASE_W * self._scale)
        h = int(self._base_h() * self._scale)
        self.setFixedSize(w, h)
        # При первом запуске — по центру сверху
        if not hasattr(self, '_pos_set'):
            self.move(sw // 2 - w // 2, 14)
            self._pos_set = True

    # ── public API ─────────────────────────────────────────────────
    def set_fps(self, fps):   self._fps  = fps
    def set_ping(self, ping): self._ping = ping
    def set_music(self, track):
        self._music = track[:50] if track else "No Music"
    def set_animation(self, en):
        self._anim_en = en
    def set_size(self, scale):
        self._scale = max(0.5, min(2.0, scale))
        self._reposition()
    def set_visible(self, v):
        self._visible = v;  self.setVisible(v)
    def set_show_fps(self, v):   self._show_fps  = v
    def set_show_ping(self, v):  self._show_ping = v
    def set_show_music(self, v):
        self._show_music = v
        self._reposition()

    # ── animation tick ─────────────────────────────────────────────
    def set_tick_callback(self, cb):
        """Коллбэк вызывается каждый кадр (для подсчёта FPS)."""
        self._tick_callback = cb

    def _tick_fn(self):
        if self._anim_en:
            self._tick = (self._tick + 1) % 3600
            # ZEUS пульс: 0→1→0 за ~2 сек
            self._zeus_alpha = 0.5 + 0.5 * math.sin(math.radians(self._tick * 1.8))
        if hasattr(self, '_tick_callback') and self._tick_callback:
            self._tick_callback()
        self.update()

    # ── mouse ──────────────────────────────────────────────────────
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            # Проверка клик на кнопку стрелки (нижний центр)
            w, h = self.width(), self.height()
            arrow_rect = QRect(w//2 - 16, h - 18, 32, 16)
            pos = e.pos()
            px = int(pos.x()) if hasattr(pos, 'x') else pos.x()
            py = int(pos.y()) if hasattr(pos, 'y') else pos.y()
            if arrow_rect.contains(px, py):
                self._music_expanded = not self._music_expanded
                self._reposition()
                return
            self._dragging = True
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._dragging:
            self.move(e.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, e):
        self._dragging = False

    # ── paint ──────────────────────────────────────────────────────
    def paintEvent(self, e):
        if not self._visible:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        w, h = self.width(), self.height()
        pad = 10
        r   = 22  # corner radius

        # ── glass background ──────────────────────────────────────
        body = QPainterPath()
        body.addRoundedRect(pad, 4, w - 2*pad, h - 8, r, r)

        # deep translucent fill — glass effect
        bg_grad = QLinearGradient(0, 0, 0, h)
        bg_grad.setColorAt(0.0, QColor(45, 38, 30, 195))
        bg_grad.setColorAt(0.5, QColor(30, 24, 18, 210))
        bg_grad.setColorAt(1.0, QColor(20, 16, 12, 200))
        p.fillPath(body, bg_grad)

        # inner glow (beige tint top)
        top_sheen = QLinearGradient(0, 4, 0, 4 + (h-8)*0.45)
        top_sheen.setColorAt(0, QColor(230, 215, 185, 28))
        top_sheen.setColorAt(1, QColor(217, 199, 168, 0))
        p.fillPath(body, top_sheen)

        # border glow
        border_grad = QLinearGradient(pad, 0, w-pad, h)
        border_grad.setColorAt(0.0, QColor(217, 199, 168, 60))
        border_grad.setColorAt(0.5, QColor(240, 224, 192, 140))
        border_grad.setColorAt(1.0, QColor(200, 182, 148, 55))
        p.setPen(QPen(border_grad, 1.5))
        p.drawPath(body)

        # ── stars animation ───────────────────────────────────────
        if self._anim_en:
            inner_x = pad + 2
            inner_w = w - 2*pad - 4
            inner_h = h - 12
            for (rx, ry, phase, sz) in self._stars:
                sx = inner_x + rx * inner_w
                sy = 6 + ry * inner_h
                alpha = int(220 * (0.3 + 0.7 * abs(math.sin(
                    math.radians(self._tick * 1.2 + phase)))))
                size  = sz * (0.6 + 0.4 * abs(math.sin(
                    math.radians(self._tick * 0.8 + phase + 45))))
                star_col = QColor(GLOW_RGB[0], GLOW_RGB[1], GLOW_RGB[2], alpha)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(star_col)
                p.drawEllipse(
                    int(sx - size/2), int(sy - size/2),
                    int(size), int(size))

        sc = self._scale
        # ── layout zones ──────────────────────────────────────────
        # Left column: FPS
        # Center: ZEUS / MIDNIGHT
        # Right column: PING
        # Bottom (if expanded): music + arrow

        lx = pad + 10          # left text x
        rx_col = w - pad - 10  # right text right edge
        cx_mid = w // 2

        top_zone_h = int(self.BASE_H_MINI * sc) - 10

        # ── FPS (left) ────────────────────────────────────────────
        if self._show_fps:
            fps_val = str(self._fps)
            p.setFont(_font(int(14 * sc), QFont.Weight.ExtraBold))
            p.setPen(QColor(TEXT_PRI))
            p.drawText(QRect(lx, 12, 70, int(20*sc)), Qt.AlignmentFlag.AlignLeft, fps_val)
            p.setFont(_font(int(7 * sc)))
            p.setPen(QColor(TEXT_MUT))
            p.drawText(QRect(lx, int(12 + 18*sc), 70, int(14*sc)),
                       Qt.AlignmentFlag.AlignLeft, "FPS")

        # ── PING (right) ──────────────────────────────────────────
        if self._show_ping:
            ping_col = QColor(SUCCESS) if self._ping < 100 else QColor(WARNING)
            p.setFont(_font(int(14 * sc), QFont.Weight.ExtraBold))
            p.setPen(ping_col)
            p.drawText(QRect(rx_col - 70, 12, 70, int(20*sc)),
                       Qt.AlignmentFlag.AlignRight, str(self._ping))
            p.setFont(_font(int(7 * sc)))
            p.setPen(QColor(TEXT_MUT))
            p.drawText(QRect(rx_col - 70, int(12 + 18*sc), 70, int(14*sc)),
                       Qt.AlignmentFlag.AlignRight, "ms PING")

        # ── ZEUS (center, breathing) ──────────────────────────────
        zeus_a = int(self._zeus_alpha * 255) if self._anim_en else 200
        p.setFont(_font(int(13 * sc), QFont.Weight.Black))
        p.setPen(QColor(217, 199, 168, zeus_a))
        p.drawText(QRect(cx_mid - 60, 10, 120, int(22*sc)),
                   Qt.AlignmentFlag.AlignCenter, "ZEUS")

        # MIDNIGHT (below ZEUS, dimmer)
        mid_a = int(self._zeus_alpha * 140 + 60) if self._anim_en else 120
        p.setFont(_font(int(7 * sc), QFont.Weight.DemiBold))
        p.setPen(QColor(180, 162, 132, mid_a))
        p.drawText(QRect(cx_mid - 60, int(10 + 20*sc), 120, int(12*sc)),
                   Qt.AlignmentFlag.AlignCenter, "MIDNIGHT")

        # ── divider line ─────────────────────────────────────────
        if self._show_music:
            div_y = top_zone_h - 4
            div_grad = QLinearGradient(pad+20, div_y, w-pad-20, div_y)
            div_grad.setColorAt(0, QColor(217, 199, 168, 0))
            div_grad.setColorAt(0.5, QColor(217, 199, 168, 55))
            div_grad.setColorAt(1, QColor(217, 199, 168, 0))
            p.setPen(QPen(div_grad, 1))
            p.drawLine(pad+20, div_y, w-pad-20, div_y)

        # ── MUSIC row (bottom, collapsible) ──────────────────────
        if self._show_music:
            music_y = top_zone_h + 2
            if self._music_expanded:
                p.setFont(_font(int(9 * sc)))
                p.setPen(QColor(TEXT_MUT))
                # truncate if needed
                fm = QFontMetrics(p.font())
                max_w = w - 2*pad - 30
                txt = fm.elidedText(self._music, Qt.TextElideMode.ElideRight, max_w)
                p.drawText(QRect(lx, music_y, w - 2*lx - 20, int(16*sc)),
                           Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                           txt)

            # ── collapse arrow ────────────────────────────────────
            arrow_cx = cx_mid
            arrow_y  = h - 14
            arrow_w  = 14
            p.setPen(QPen(QColor(217, 199, 168, 160), 1.8,
                          Qt.PenStyle.SolidLine,
                          Qt.PenCapStyle.RoundCap,
                          Qt.PenJoinStyle.RoundJoin))
            if self._music_expanded:
                # up arrow (свернуть)
                p.drawLine(arrow_cx - arrow_w, arrow_y + 5,
                           arrow_cx,             arrow_y)
                p.drawLine(arrow_cx,             arrow_y,
                           arrow_cx + arrow_w,   arrow_y + 5)
            else:
                # down arrow (развернуть)
                p.drawLine(arrow_cx - arrow_w, arrow_y,
                           arrow_cx,             arrow_y + 5)
                p.drawLine(arrow_cx,             arrow_y + 5,
                           arrow_cx + arrow_w,   arrow_y)


# ═══════════════════════════════════════════════════════════════════
#  CUSTOM CROSSHAIR WIDGET — полностью переработан
#  Форма: 4 полых прямоугольных линии (как на картинке), без точки
#  Анимация только Star Twinkle внутри линий
#  Glass эффект с прозрачностью
# ═══════════════════════════════════════════════════════════════════
class CustomCrosshair(QWidget):
    class AnimationType(Enum):
        STAR_TWINKLE = 1
        NONE = 2

    # базовые размеры одного плеча (используются только как точка отсчёта
    # для масштаба звёзд-анимации — сами параметры теперь независимы и
    # не имеют верхнего ограничения, кроме разумного программного предела)
    BASE_LEN   = 22    # длина плеча по умолчанию, px
    BASE_THICK = 7     # толщина плеча по умолчанию, px
    BASE_GAP   = 5     # зазор от центра до начала плеча по умолчанию, px

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._dragging   = False
        self._drag_pos   = None
        self._color      = QColor(ACCENT)
        self._anim_type  = self.AnimationType.STAR_TWINKLE
        self._tick       = 0
        self._visible    = True

        # независимые параметры прицела — каждый меняется отдельно
        self._gap     = self.BASE_GAP    # зазор от центра, px
        self._thick   = self.BASE_THICK  # толщина плеча, px
        self._len     = self.BASE_LEN    # длина плеча, px
        self._opacity = 100              # прозрачность всего прицела, % (0-100)

        import random; random.seed(99)
        self._arm_stars = [
            [(p, random.uniform(0.15, 0.85), random.uniform(0, 360), random.uniform(1.0, 2.0))
             for p in [0.1, 0.3, 0.55, 0.75, 0.92]]
            for _ in range(4)
        ]

        self._reposition()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick_fn)
        self._timer.start(16)

    def _size(self):
        # виджет должен вмещать самое длинное плечо + зазор + запас на скругления
        needed = 2 * (self._gap + self._len) + self._thick + 24
        return max(40, int(needed))

    def _arm_len(self):
        return max(1, int(self._len))

    def _arm_thick(self):
        return max(1, int(self._thick))

    def _arm_gap(self):
        return max(0, int(self._gap))

    def _reposition(self):
        sz = self._size()
        self.setFixedSize(sz, sz)
        # Всегда центрируем по монитору
        screen = QApplication.primaryScreen().geometry()
        self.move(screen.width()//2 - sz//2, screen.height()//2 - sz//2)

    # ── public API ─────────────────────────────────────────────────
    def set_color(self, color):
        self._color = color

    def set_animation(self, anim_type):
        self._anim_type = anim_type

    def set_visible(self, v):
        self._visible = v
        self.setVisible(v)

    def set_gap(self, px):
        """Зазор от центра до начала плеча, без ограничений сверху."""
        self._gap = max(0, int(px))
        self._reposition()

    def set_thickness(self, px):
        """Толщина плеча, без ограничений сверху."""
        self._thick = max(1, int(px))
        self._reposition()

    def set_length(self, px):
        """Длина плеча, без ограничений сверху."""
        self._len = max(1, int(px))
        self._reposition()

    def set_opacity(self, pct):
        """Прозрачность всего прицела, 0-100%."""
        self._opacity = max(0, min(100, int(pct)))

    def _tick_fn(self):
        self._tick = (self._tick + 1) % 3600
        self.update()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._dragging = True
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._dragging:
            self.move(e.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, e):
        self._dragging = False

    def paintEvent(self, e):
        if not self._visible:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setOpacity(self._opacity / 100.0)

        w, h   = self.width(), self.height()
        cx, cy = w // 2, h // 2

        arm_len   = self._arm_len()
        arm_thick = self._arm_thick()
        arm_gap   = self._arm_gap()
        # масштаб для звёзд анимации — относительно толщины плеча
        star_scale = arm_thick / float(self.BASE_THICK)

        # ── Четыре плеча: UP DOWN LEFT RIGHT ─────────────────────
        # Каждое плечо — полый прямоугольник (glass + border + stars внутри)
        #
        # ARM RECTS (в локальных координатах):
        #   UP:    x=cx-T/2, y=cy-gap-len,  w=T, h=len
        #   DOWN:  x=cx-T/2, y=cy+gap,       w=T, h=len
        #   LEFT:  x=cx-gap-len, y=cy-T/2,   w=len, h=T
        #   RIGHT: x=cx+gap,     y=cy-T/2,   w=len, h=T

        # Все четыре плеча одинаковой длины
        arms = [
            QRectF(cx - arm_thick/2, cy - arm_gap - arm_len, arm_thick, arm_len),   # UP
            QRectF(cx - arm_thick/2, cy + arm_gap,            arm_thick, arm_len),   # DOWN
            QRectF(cx - arm_gap - arm_len, cy - arm_thick/2,  arm_len, arm_thick),  # LEFT
            QRectF(cx + arm_gap,           cy - arm_thick/2,  arm_len, arm_thick),  # RIGHT
        ]
        # направление «вдоль» для каждого плеча (единичный вектор)
        arm_along  = [(0,-1), (0,1), (-1,0), (1,0)]
        arm_across = [(1,0),  (1,0), (0,1),  (0,1)]

        c = self._color

        for i, rect in enumerate(arms):
            path = QPainterPath()
            path.addRoundedRect(rect, 3, 3)

            # ── glass fill ──────────────────────────────────────
            # Направление градиента: вдоль плеча от центра к кончику
            (dx, dy) = arm_along[i]
            gx0 = rect.center().x() - dx * rect.width()//2
            gy0 = rect.center().y() - dy * rect.height()//2
            gx1 = rect.center().x() + dx * rect.width()//2
            gy1 = rect.center().y() + dy * rect.height()//2

            fill = QLinearGradient(gx0, gy0, gx1, gy1)
            base_a = 60    # прозрачный glass
            fill.setColorAt(0.0, QColor(c.red(), c.green(), c.blue(), base_a + 20))
            fill.setColorAt(0.5, QColor(c.red(), c.green(), c.blue(), base_a))
            fill.setColorAt(1.0, QColor(c.red(), c.green(), c.blue(), base_a - 15))
            p.fillPath(path, fill)

            # top/bottom sheen (перпендикулярный градиент для glass)
            (ax, ay) = arm_across[i]
            sx0 = rect.x() + ax * 0
            sy0 = rect.y() + ay * 0
            sx1 = rect.x() + ax * rect.width()
            sy1 = rect.y() + ay * rect.height()
            sheen = QLinearGradient(sx0, sy0, sx1, sy1)
            sheen.setColorAt(0, QColor(255, 252, 244, 45))
            sheen.setColorAt(0.4, QColor(255, 252, 244, 8))
            sheen.setColorAt(1, QColor(255, 252, 244, 0))
            p.fillPath(path, sheen)

            # ── border ───────────────────────────────────────────
            border_a = 200
            p.setPen(QPen(QColor(c.red(), c.green(), c.blue(), border_a), 1.5))
            p.drawPath(path)

            # ── star twinkle inside arm ───────────────────────────
            if self._anim_type == self.AnimationType.STAR_TWINKLE:
                p.setPen(Qt.PenStyle.NoPen)
                for (along_t, across_t, phase, sz) in self._arm_stars[i]:
                    # позиция вдоль плеча
                    if i == 0:  # UP: y идёт от bottom к top
                        sx = rect.x() + across_t * rect.width()
                        sy = rect.bottom() - along_t * rect.height()
                    elif i == 1:  # DOWN
                        sx = rect.x() + across_t * rect.width()
                        sy = rect.top() + along_t * rect.height()
                    elif i == 2:  # LEFT
                        sx = rect.right() - along_t * rect.width()
                        sy = rect.y() + across_t * rect.height()
                    else:  # RIGHT
                        sx = rect.left() + along_t * rect.width()
                        sy = rect.y() + across_t * rect.height()

                    star_a = int(230 * (0.2 + 0.8 * abs(math.sin(
                        math.radians(self._tick * 2.0 + phase)))))
                    star_sz = sz * star_scale * (0.7 + 0.3 * abs(math.sin(
                        math.radians(self._tick * 1.5 + phase + 60))))
                    star_col = QColor(255, 248, 220, star_a)   # тёплый белый
                    p.setBrush(star_col)
                    p.drawEllipse(int(sx - star_sz/2), int(sy - star_sz/2),
                                  max(1, int(star_sz)), max(1, int(star_sz)))


# ═══════════════════════════════════════════════════════════════════
#  STATS MONITOR
# ═══════════════════════════════════════════════════════════════════
class StatsMonitor(QThread):
    """Реальный FPS через счётчик кадров + пинг через TCP-сокет."""
    fps_updated  = pyqtSignal(int)
    ping_updated = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self._running      = True
        self._frame_count  = 0   # инкрементируется из UI таймера

    def count_frame(self):
        """Вызывается каждый кадр DynamicIsland._tick_fn из UI-потока."""
        self._frame_count += 1

    def run(self):
        import threading, socket

        self._ping_running = True

        def ping_loop():
            while self._ping_running:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    t0 = time.perf_counter()
                    s.connect(("8.8.8.8", 53))
                    s.close()
                    ms = int((time.perf_counter() - t0) * 1000)
                    if 0 < ms < 9999:
                        self.ping_updated.emit(ms)
                except Exception:
                    pass
                time.sleep(3)

        pt = threading.Thread(target=ping_loop, daemon=True)
        pt.start()

        last = time.time()
        while self._running:
            time.sleep(1.0)
            now = time.time()
            elapsed = now - last
            if elapsed > 0:
                fps = min(int(self._frame_count / elapsed), 999)
                self.fps_updated.emit(fps)
            self._frame_count = 0
            last = now

        self._ping_running = False

    def stop(self):
        self._running = False


# ═══════════════════════════════════════════════════════════════════
#  MUSIC ICON BUTTON - Custom painted, no emoji/text symbols
# ═══════════════════════════════════════════════════════════════════
class MusicIconButton(QWidget):
    """Button with a custom-painted music control icon."""
    clicked = pyqtSignal()
    
    PREV = "prev"
    PLAY = "play"
    PAUSE = "pause"
    NEXT = "next"

    def __init__(self, icon_type, parent=None):
        super().__init__(parent)
        self._icon = icon_type
        self._hovered = False
        self._pressed = False
        self.setFixedSize(56, 44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMouseTracking(True)

    def set_icon(self, icon_type):
        self._icon = icon_type
        self.update()

    def enterEvent(self, e):
        self._hovered = True
        self.update()

    def leaveEvent(self, e):
        self._hovered = False
        self._pressed = False
        self.update()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._pressed = True
            self.update()

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._pressed = False
            self.update()
            if self.rect().contains(e.pos()):
                self.clicked.emit()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        # Button background — glass beige
        path = QPainterPath()
        path.addRoundedRect(0, 0, w, h, 10, 10)
        
        if self._pressed:
            bg = QLinearGradient(0, 0, 0, h)
            bg.setColorAt(0, QColor(217, 199, 168, 14))
            bg.setColorAt(1, QColor(190, 172, 140, 7))
        elif self._hovered:
            bg = QLinearGradient(0, 0, 0, h)
            bg.setColorAt(0, QColor(230, 215, 188, 55))
            bg.setColorAt(1, QColor(200, 182, 148, 25))
        else:
            bg = QLinearGradient(0, 0, 0, h)
            bg.setColorAt(0, QColor(217, 199, 168, 28))
            bg.setColorAt(1, QColor(190, 172, 140, 12))
        p.fillPath(path, bg)
        
        # Top sheen
        sheen = QPainterPath()
        sheen.addRoundedRect(1, 1, w-2, h//2-1, 9, 9)
        sg = QLinearGradient(0, 0, 0, h//2)
        sg.setColorAt(0, QColor(255, 252, 244, 50 if self._hovered else 28))
        sg.setColorAt(1, QColor(255, 252, 244, 0))
        p.fillPath(sheen, sg)
        
        # Border
        bord_a = 120 if self._hovered else 60
        p.setPen(QPen(QColor(217, 199, 168, bord_a), 1.0))
        p.drawPath(path)
        
        # Icon color
        ic = QColor(240, 228, 205) if self._hovered else QColor(210, 195, 168)
        if self._pressed:
            ic = QColor(180, 165, 140)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(ic)
        
        cx, cy = w // 2, h // 2

        if self._icon == self.PLAY:
            # Triangle play icon, centered
            pts = [
                QPoint(cx - 7, cy - 9),
                QPoint(cx - 7, cy + 9),
                QPoint(cx + 9, cy),
            ]
            from PyQt6.QtGui import QPolygon
            p.drawPolygon(QPolygon(pts))

        elif self._icon == self.PAUSE:
            # Two rectangles
            p.drawRoundedRect(cx - 8, cy - 8, 5, 16, 2, 2)
            p.drawRoundedRect(cx + 3, cy - 8, 5, 16, 2, 2)

        elif self._icon == self.PREV:
            # Vertical bar + left triangle
            p.drawRoundedRect(cx - 10, cy - 8, 4, 16, 2, 2)
            from PyQt6.QtGui import QPolygon
            tri = [
                QPoint(cx - 3, cy),
                QPoint(cx + 8, cy - 9),
                QPoint(cx + 8, cy + 9),
            ]
            p.drawPolygon(QPolygon(tri))

        elif self._icon == self.NEXT:
            # Right triangle + vertical bar
            from PyQt6.QtGui import QPolygon
            tri = [
                QPoint(cx + 3, cy),
                QPoint(cx - 8, cy - 9),
                QPoint(cx - 8, cy + 9),
            ]
            p.drawPolygon(QPolygon(tri))
            p.drawRoundedRect(cx + 6, cy - 8, 4, 16, 2, 2)


# ═══════════════════════════════════════════════════════════════════
#  MUSIC CONTROLLER
# ═══════════════════════════════════════════════════════════════════
class MusicController(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._is_playing = False
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        self.prev_btn = MusicIconButton(MusicIconButton.PREV)
        self.prev_btn.clicked.connect(self._previous_track)
        layout.addWidget(self.prev_btn)
        
        self.play_btn = MusicIconButton(MusicIconButton.PLAY)
        self.play_btn.clicked.connect(self._toggle_play)
        layout.addWidget(self.play_btn)
        
        self.next_btn = MusicIconButton(MusicIconButton.NEXT)
        self.next_btn.clicked.connect(self._next_track)
        layout.addWidget(self.next_btn)
        
        layout.addStretch()
        
    def _previous_track(self):
        self._send_media_key(173)
        
    def _toggle_play(self):
        self._is_playing = not self._is_playing
        self.play_btn.set_icon(
            MusicIconButton.PAUSE if self._is_playing else MusicIconButton.PLAY
        )
        self._send_media_key(179)
        
    def _next_track(self):
        self._send_media_key(176)
        
    def _send_media_key(self, vk):
        try:
            ctypes.windll.user32.keybd_event(vk, 0, 0, 0)
            time.sleep(0.05)
            ctypes.windll.user32.keybd_event(vk, 0, 2, 0)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════
#  GLASS CARD
# ═══════════════════════════════════════════════════════════════════
class GlassCard(QWidget):
    def __init__(self, tint=CARD_TINT, radius=14, parent=None):
        super().__init__(parent)
        self._tint, self._radius = tint, radius
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width(), self.height(), self._radius, self._radius)
        r,g,b,a = self._tint
        p.fillPath(path, QColor(r,g,b,a))
        p.setPen(QPen(QColor(217, 199, 168, 50), 1))
        p.drawPath(path)
        hi = QPainterPath()
        hi.addRoundedRect(1, 1, self.width()-2, 2, self._radius, self._radius)
        p.fillPath(hi, QColor(217, 199, 168, 30))


# ═══════════════════════════════════════════════════════════════════
#  GLOW BUTTON - УЛУЧШЕННЫЙ С БОЛЬШЕ БЛЮРА
# ═══════════════════════════════════════════════════════════════════
class GlowButton(QWidget):
    clicked = pyqtSignal()

    def __init__(self, text, variant="gold", parent=None):
        super().__init__(parent)
        self._text    = text
        self._variant = variant
        self._hovered = False
        self._pressed = False
        self._enabled = True
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMouseTracking(True)

        if variant == "gold":
            self.setFixedHeight(46)
        elif variant == "ghost":
            self.setFixedHeight(38)
        else:
            self.setFixedHeight(32)

    def setEnabled(self, v):
        self._enabled = v
        self.update()
        super().setEnabled(v)

    def setText(self, t):
        self._text = t
        self.update()

    def enterEvent(self, e):
        self._hovered = True
        self.update()

    def leaveEvent(self, e):
        self._hovered = False
        self._pressed = False
        self.update()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and self._enabled:
            self._pressed = True
            self.update()

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and self._enabled:
            self._pressed = False
            self.update()
            if self.rect().contains(e.pos()):
                self.clicked.emit()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        r = h // 2 - 1

        path = QPainterPath()
        path.addRoundedRect(0, 0, w, h, r, r)

        if not self._enabled:
            p.fillPath(path, QColor(217, 199, 168, 8))
            p.setPen(QPen(QColor(217, 199, 168, 25), 1))
            p.drawPath(path)
            p.setPen(QColor(TEXT_DIM))
            p.setFont(_font(10, QFont.Weight.Bold))
            p.drawText(QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, self._text)
            return

        v = self._variant

        # ── Fill alphas per variant ──────────────────────────────────
        if v == "gold":
            base_a, hover_a, press_a = 28, 55, 14
            border_a_base, border_a_hov = 65, 140
        elif v == "ghost":
            base_a, hover_a, press_a = 16, 34, 8
            border_a_base, border_a_hov = 45, 90
        else:  # action / small
            base_a, hover_a, press_a = 18, 36, 9
            border_a_base, border_a_hov = 50, 100

        # ── Background gradient (glass beige) ────────────────────────
        bg = QLinearGradient(0, 0, 0, h)
        if self._pressed:
            bg.setColorAt(0, QColor(217, 199, 168, press_a))
            bg.setColorAt(1, QColor(190, 172, 140, press_a // 2))
        elif self._hovered:
            bg.setColorAt(0, QColor(230, 215, 188, hover_a))
            bg.setColorAt(1, QColor(200, 182, 148, hover_a // 2))
        else:
            bg.setColorAt(0, QColor(217, 199, 168, base_a))
            bg.setColorAt(1, QColor(190, 172, 140, base_a // 2))
        p.fillPath(path, bg)

        # ── Border (glowing on hover) ─────────────────────────────────
        border_alpha = border_a_hov if self._hovered else border_a_base
        if v == "gold" and self._hovered:
            # Gradient border for gold hover
            pen_col = QColor(230, 215, 185, border_alpha)
        else:
            pen_col = QColor(217, 199, 168, border_alpha)
        p.setPen(QPen(pen_col, 1.2 if self._hovered else 1.0))
        p.drawPath(path)

        # ── Top sheen (frosted glass highlight) ──────────────────────
        sheen = QPainterPath()
        sheen.addRoundedRect(1, 1, w - 2, h // 2 - 1, r - 1, r - 1)
        sg = QLinearGradient(0, 0, 0, h // 2)
        sheen_a = 60 if self._hovered else 35
        sg.setColorAt(0, QColor(255, 252, 244, sheen_a))
        sg.setColorAt(1, QColor(255, 252, 244, 0))
        p.fillPath(sheen, sg)

        # ── Bottom glow reflection ────────────────────────────────────
        if v == "gold":
            bot_sheen = QPainterPath()
            bot_sheen.addRoundedRect(1, h // 2, w - 2, h // 2 - 1, r - 1, r - 1)
            bsg = QLinearGradient(0, h // 2, 0, h)
            bsg.setColorAt(0, QColor(217, 199, 168, 0))
            bsg.setColorAt(1, QColor(217, 199, 168, 18 if self._hovered else 8))
            p.fillPath(bot_sheen, bsg)

        # ── Text ──────────────────────────────────────────────────────
        if v == "gold":
            text_col = QColor(240, 230, 210) if self._hovered else QColor(TEXT_PRI)
            weight = QFont.Weight.ExtraBold
            size = 11
        elif v == "ghost":
            text_col = QColor(ACCENT) if self._hovered else QColor(TEXT_PRI)
            weight = QFont.Weight.Bold
            size = 10
        else:
            text_col = QColor(ACCENT) if self._hovered else QColor(TEXT_PRI)
            weight = QFont.Weight.Bold
            size = 9
        p.setPen(text_col)
        p.setFont(_font(size, weight))
        p.drawText(QRect(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, self._text)


# ═══════════════════════════════════════════════════════════════════
#  ARC GAUGE
# ═══════════════════════════════════════════════════════════════════
class ArcGauge(QWidget):
    def __init__(self, label="", color=ACCENT, size=148, parent=None):
        super().__init__(parent)
        self._val, self._label, self._color, self._sz = 0, label, QColor(color), size
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    def setValue(self, v):
        self._val = max(0, min(100, v))
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        r = h // 2 - 8
        cx, cy = w // 2, h // 2
        p.setPen(QPen(QColor(217, 199, 168, 15), 4))
        p.drawArc(QRect(cx-r, cy-r, r*2, r*2), 45*16, 270*16)
        p.setPen(QPen(self._color, 4))
        p.drawArc(QRect(cx-r, cy-r, r*2, r*2), 45*16, int(270*16*self._val/100))
        p.setPen(QColor(TEXT_PRI))
        p.setFont(_font(int(self._sz*0.16), QFont.Weight.ExtraBold))
        p.drawText(QRect(0, cy-int(self._sz*.21), w, int(self._sz*.26)),
                   Qt.AlignmentFlag.AlignHCenter, f"{int(self._val)}%")
        p.setPen(QColor(TEXT_MUT))
        p.setFont(_font(int(self._sz*0.067)))
        p.drawText(QRect(0, cy+int(self._sz*.065), w, int(self._sz*.15)),
                   Qt.AlignmentFlag.AlignHCenter, self._label)


# ═══════════════════════════════════════════════════════════════════
#  MINI BAR
# ═══════════════════════════════════════════════════════════════════
class MiniBar(QWidget):
    def __init__(self, label, parent=None):
        super().__init__(parent)
        self._label, self._val = label, 0
        self.setFixedHeight(36)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    def setValue(self, v):
        self._val = max(0, min(100, v))
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(QColor(TEXT_MUT))
        p.setFont(_font(9))
        p.drawText(0, 0, w-44, 18, Qt.AlignmentFlag.AlignLeft|Qt.AlignmentFlag.AlignVCenter, self._label)
        p.setPen(QColor(TEXT_PRI))
        p.setFont(_font(9, QFont.Weight.Bold))
        p.drawText(w-42,0,42,18, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter, f"{int(self._val)}%")
        by, bh = 25, 4
        tr = QPainterPath()
        tr.addRoundedRect(0, by, w, bh, 2, 2)
        p.fillPath(tr, QColor(217, 199, 168, 20))
        if self._val > 0:
            col = QColor(ACCENT)
            if self._val > 85: col = QColor(DANGER)
            elif self._val > 65: col = QColor(WARNING)
            gr = QLinearGradient(0,0,w,0)
            gr.setColorAt(0, col)
            c2=QColor(col)
            c2.setAlpha(160)
            gr.setColorAt(1,c2)
            fl = QPainterPath()
            fl.addRoundedRect(0, by, int(w*self._val/100), bh, 2, 2)
            p.fillPath(fl, gr)


# ═══════════════════════════════════════════════════════════════════
#  NAV BUTTON
# ═══════════════════════════════════════════════════════════════════
class NavButton(QWidget):
    clicked = pyqtSignal()

    def __init__(self, icon_char, text, parent=None):
        super().__init__(parent)
        self._icon, self._text, self._active = icon_char, text, False
        self._hov = False
        self.setFixedHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMouseTracking(True)

    def setActive(self, v):
        self._active = v
        self.update()

    def enterEvent(self, e):
        self._hov = True
        self.update()

    def leaveEvent(self, e):
        self._hov = False
        self.update()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        path = QPainterPath()
        path.addRoundedRect(6, 2, w-12, h-4, 10, 10)

        if self._active:
            # Active: warm beige glass fill
            fill_grad = QLinearGradient(0, 0, w, h)
            fill_grad.setColorAt(0, QColor(217, 199, 168, 55))
            fill_grad.setColorAt(1, QColor(200, 182, 148, 30))
            p.fillPath(path, fill_grad)
            # Top sheen
            sheen = QPainterPath()
            sheen.addRoundedRect(7, 3, w-14, (h-4)//2, 9, 9)
            sg = QLinearGradient(0, 0, 0, h)
            sg.setColorAt(0, QColor(255, 248, 235, 40))
            sg.setColorAt(1, QColor(255, 248, 235, 0))
            p.fillPath(sheen, sg)
            # Gold border
            p.setPen(QPen(QColor(217, 199, 168, 100), 1))
            p.drawPath(path)
            # Active bar left side
            bar = QPainterPath()
            bar.addRoundedRect(6, 10, 3, h-20, 2, 2)
            g = QLinearGradient(0, 10, 0, h-10)
            g.setColorAt(0, QColor(ACCENT))
            g.setColorAt(1, QColor(ACCENT3))
            p.fillPath(bar, g)
        elif self._hov:
            # Hover: lighter glass
            fill_grad = QLinearGradient(0, 0, w, h)
            fill_grad.setColorAt(0, QColor(217, 199, 168, 30))
            fill_grad.setColorAt(1, QColor(200, 182, 148, 15))
            p.fillPath(path, fill_grad)
            p.setPen(QPen(QColor(217, 199, 168, 55), 1))
            p.drawPath(path)

        # Icon
        icon_col = QColor(ACCENT) if self._active else (QColor(TEXT_PRI) if self._hov else QColor(170, 158, 138))
        p.setPen(icon_col)
        p.setFont(_font(13))
        p.drawText(QRect(18, 0, 26, h), Qt.AlignmentFlag.AlignVCenter, self._icon)

        # Label
        fw = QFont.Weight.DemiBold if self._active else QFont.Weight.Normal
        label_col = QColor(TEXT_PRI) if self._active else (QColor(TEXT_PRI) if self._hov else QColor(160, 148, 130))
        p.setPen(label_col)
        p.setFont(_font(10, fw))
        p.drawText(QRect(50, 0, w-60, h), Qt.AlignmentFlag.AlignVCenter, self._text)


# ═══════════════════════════════════════════════════════════════════
#  GRAPH WIDGET
# ═══════════════════════════════════════════════════════════════════
class GraphWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._cpu, self._ram = [0]*60, [0]*60
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    def update_data(self, cpu, ram):
        self._cpu, self._ram = cpu, ram
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        pad = 14

        bg = QPainterPath()
        bg.addRoundedRect(0,0,w,h,12,12)
        p.fillPath(bg, QColor(25, 22, 20, 150))
        p.setPen(QPen(QColor(217, 199, 168, 25),1))
        p.drawPath(bg)

        def draw(data, hex_c):
            n   = len(data)
            lp  = QPainterPath()
            fp = QPainterPath()
            pts = [(pad+(w-2*pad)*i/(n-1), pad+(h-2*pad)*(1-v/100)) for i,v in enumerate(data)]
            lp.moveTo(*pts[0])
            fp.moveTo(pts[0][0], h-pad)
            fp.lineTo(*pts[0])
            for x,y in pts[1:]:
                lp.lineTo(x,y)
                fp.lineTo(x,y)
            fp.lineTo(pts[-1][0], h-pad)
            fp.closeSubpath()
            gr = QLinearGradient(0,pad,0,h-pad)
            c=QColor(hex_c)
            c.setAlpha(80)
            gr.setColorAt(0,c)
            c2=QColor(hex_c)
            c2.setAlpha(0)
            gr.setColorAt(1,c2)
            p.fillPath(fp, gr)
            pen=QPen(QColor(hex_c))
            pen.setWidth(2)
            p.setPen(pen)
            p.drawPath(lp)

        p.setPen(QPen(QColor(217, 199, 168, 10)))
        for pc in [25,50,75]:
            y=pad+(h-2*pad)*(1-pc/100)
            p.drawLine(int(pad),int(y),int(w-pad),int(y))

        draw(self._cpu,"#60a5fa")
        draw(self._ram,"#a78bfa")

        for i,(lb,col) in enumerate([("CPU","#60a5fa"),("RAM","#a78bfa")]):
            x=w-88+i*46
            dot=QPainterPath()
            dot.addEllipse(x,9,6,6)
            p.fillPath(dot,QColor(col))
            p.setPen(QColor(TEXT_MUT))
            p.setFont(_font(8))
            p.drawText(x+10,17,lb)


# ═══════════════════════════════════════════════════════════════════
#  HELPER
# ═══════════════════════════════════════════════════════════════════
def _tl(text, style):
    l=QLabel(text)
    if "font-family" not in style and "font:" not in style:
        style = f"font-family:'{FONT_FAMILY}';" + style
    l.setStyleSheet(style)
    l.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
    return l


# ═══════════════════════════════════════════════════════════════════
#  DASHBOARD PAGE
# ═══════════════════════════════════════════════════════════════════
class DashboardPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._setup()

    def _setup(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(26,22,26,22)
        root.setSpacing(14)

        r1=QHBoxLayout()
        r1.setSpacing(14)

        hero=GlassCard((30, 26, 24, 160),16)
        hero.setMinimumHeight(188)
        hl=QVBoxLayout(hero)
        hl.setContentsMargins(30,28,30,28)
        hl.setSpacing(7)
        hl.addWidget(_tl(t("welcome"),f"color:{TEXT_MUT};font-size:13px;font-weight:500;"))
        hl.addWidget(_tl(t("optimize_slogan"),f"color:{TEXT_PRI};font-size:26px;font-weight:800;"))
        hl.addWidget(_tl(t("optimize_desc"),f"color:{TEXT_MUT};font-size:11px;font-weight:400;"))
        hl.addSpacing(10)
        self.opt_btn=GlowButton(t("optimize_btn"),"gold")
        self.opt_btn.setFixedWidth(220)
        hl.addWidget(self.opt_btn)
        hl.addStretch()
        r1.addWidget(hero,3)

        sc=GlassCard((30, 26, 24, 160),16)
        sc.setFixedWidth(248)
        sl=QVBoxLayout(sc)
        sl.setContentsMargins(16,16,16,16)
        sl.setSpacing(8)
        st=_tl(t("system_status"),f"color:{TEXT_MUT};font-size:9px;font-weight:600;letter-spacing:1.5px;")
        st.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sl.addWidget(st)
        self.main_g=ArcGauge(t("excellent"),ACCENT,144)
        sl.addWidget(self.main_g, alignment=Qt.AlignmentFlag.AlignCenter)
        bw=QWidget()
        bw.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        bl=QHBoxLayout(bw)
        bl.setContentsMargins(0,0,0,0)
        bl.setSpacing(8)
        self.cpu_m=MiniBar("CPU")
        self.ram_m=MiniBar("RAM")
        self.dsk_m=MiniBar("DISK")
        for b in [self.cpu_m,self.ram_m,self.dsk_m]:
            bl.addWidget(b)
        sl.addWidget(bw)
        r1.addWidget(sc)
        root.addLayout(r1)

        root.addWidget(_tl(t("quick_actions"),f"color:{TEXT_PRI};font-size:13px;font-weight:700;"))
        qa=QHBoxLayout()
        qa.setSpacing(12)
        acts=[(">","cleanup",t("cleanup"),t("cleanup_desc"),t("cleanup_btn")),
              (">","boost",t("boost"),t("boost_desc"),t("boost_btn")),
              (">","privacy",t("privacy"),t("privacy_desc"),t("privacy_btn")),
              (">","gaming",t("gaming"),t("gaming_desc"),t("gaming_btn"))]
        self.act_btns=[]
        self._gaming_active = False
        for ico,nm,nm_tr,dsc,bt in acts:
            card=GlassCard((30, 26, 24, 140),12)
            cl=QVBoxLayout(card)
            cl.setContentsMargins(14,16,14,14)
            cl.setSpacing(5)
            il=QLabel(ico)
            il.setStyleSheet("font-size:28px;")
            il.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            cl.addWidget(il)
            cl.addWidget(_tl(nm_tr,f"color:{TEXT_PRI};font-size:11px;font-weight:700;"))
            dl=_tl(dsc,f"color:{TEXT_MUT};font-size:10px;")
            dl.setWordWrap(True)
            cl.addWidget(dl)
            cl.addStretch()
            btn=GlowButton(bt,"action")
            self.act_btns.append(btn)
            cl.addWidget(btn)
            qa.addWidget(card)
        root.addLayout(qa)

        bot=QHBoxLayout()
        bot.setSpacing(12)
        sys_c=GlassCard((30, 26, 24, 140),12)
        sl2=QVBoxLayout(sys_c)
        sl2.setContentsMargins(18,14,18,14)
        sl2.setSpacing(8)
        sl2.addWidget(_tl(t("system_info"),f"color:{TEXT_PRI};font-size:12px;font-weight:700;"))
        ir=QHBoxLayout()
        ir.setSpacing(22)
        self._sys={}
        import platform
        for k,v in [("os_label",f"{platform.system()} {platform.release()}"[:14]),
                    ("uptime_label","—"),("processes_label","—")]:
            col=QVBoxLayout()
            col.setSpacing(1)
            vl=QLabel(v)
            vl.setStyleSheet(f"color:{TEXT_PRI};font-size:14px;font-weight:700;")
            vl.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            kl=_tl(t(k),f"color:{TEXT_MUT};font-size:9px;")
            col.addWidget(vl)
            col.addWidget(kl)
            self._sys[k]=vl
            ir.addLayout(col)
        ir.addStretch()
        sl2.addLayout(ir)
        bot.addWidget(sys_c,3)

        stor=GlassCard((30, 26, 24, 140),12)
        stl=QVBoxLayout(stor)
        stl.setContentsMargins(18,14,18,14)
        stl.setSpacing(8)
        stl.addWidget(_tl(t("storage"),f"color:{TEXT_PRI};font-size:12px;font-weight:700;"))
        self.db=MiniBar("C:")
        self.db2=MiniBar("Total")
        stl.addWidget(self.db)
        stl.addWidget(self.db2)
        bot.addWidget(stor,2)
        root.addLayout(bot)

    def update_stats(self, s):
        h=max(0,100-(s["cpu"]+s["ram"])/2*0.7)
        self.main_g.setValue(h)
        self.main_g._label=t("excellent") if h>75 else (t("good") if h>50 else t("load"))
        self.cpu_m.setValue(s["cpu"])
        self.ram_m.setValue(s["ram"])
        self.dsk_m.setValue(s["disk"])
        self._sys["uptime_label"].setText(s["uptime"])
        self._sys["processes_label"].setText(str(s["processes"]))
        self.db._label=f"C: {s['disk_used']}GB/{s['disk_total']}GB"
        self.db.setValue(s["disk"])
        self.db2.setValue(s["disk"])
        self.db.update()


# ═══════════════════════════════════════════════════════════════════
#  PERFORMANCE PAGE
# ═══════════════════════════════════════════════════════════════════
class PerformancePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._hc,self._hr=[0]*60,[0]*60
        self._setup()

    def _setup(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(26,22,26,22)
        root.setSpacing(14)
        root.addWidget(_tl(t("performance_monitor"),f"color:{TEXT_PRI};font-size:17px;font-weight:800;"))
        gc=GlassCard((30, 26, 24, 145),14)
        gl=QHBoxLayout(gc)
        gl.setContentsMargins(26,20,26,20)
        gl.setSpacing(32)
        self.cg=ArcGauge("CPU","#60a5fa",148)
        self.rg=ArcGauge("RAM","#a78bfa",148)
        self.dg=ArcGauge("DISK",ACCENT,148)
        for g,nm in [(self.cg,t("cpu_label")),(self.rg,t("memory_label")),(self.dg,t("disk_label"))]:
            col=QVBoxLayout()
            col.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col.addWidget(g,alignment=Qt.AlignmentFlag.AlignCenter)
            lb=_tl(nm,f"color:{TEXT_MUT};font-size:11px;")
            lb.setAlignment(Qt.AlignmentFlag.AlignCenter)
            col.addWidget(lb)
            gl.addLayout(col)
        root.addWidget(gc)
        self.graph=GraphWidget()
        self.graph.setFixedHeight(148)
        root.addWidget(self.graph)
        dc=GlassCard((30, 26, 24, 140),12)
        dl=QHBoxLayout(dc)
        dl.setContentsMargins(22,16,22,16)
        dl.setSpacing(0)
        self._det={}
        dets=[(t("cores"),str(psutil.cpu_count())),(t("ram_used"),"—"),
              (t("ram_free"),"—"),(t("disk_used"),"—"),(t("processes_label"),"—")]
        for i,(k,v) in enumerate(dets):
            col=QVBoxLayout()
            col.setSpacing(1)
            vl=QLabel(v)
            vl.setStyleSheet(f"color:{TEXT_PRI};font-size:16px;font-weight:700;")
            vl.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            kl=_tl(k,f"color:{TEXT_MUT};font-size:9px;")
            col.addWidget(vl)
            col.addWidget(kl)
            self._det[k]=vl
            dl.addLayout(col)
            if i<len(dets)-1:
                sp=QFrame()
                sp.setFixedWidth(1)
                sp.setStyleSheet("background:rgba(217,199,168,0.1);")
                dl.addWidget(sp)
                dl.addSpacing(20)
        root.addWidget(dc)

        opt_row = QHBoxLayout()
        self.opt_btn = GlowButton(t("optimize_btn"), "gold")
        self.opt_btn.setFixedWidth(280)
        opt_row.addStretch()
        opt_row.addWidget(self.opt_btn)
        opt_row.addStretch()
        root.addLayout(opt_row)

        root.addStretch()

    def update_stats(self, s):
        self.cg.setValue(s["cpu"])
        self.rg.setValue(s["ram"])
        self.dg.setValue(s["disk"])
        self._hc.append(s["cpu"])
        self._hc.pop(0)
        self._hr.append(s["ram"])
        self._hr.pop(0)
        self.graph.update_data(self._hc,self._hr)
        mem=psutil.virtual_memory()
        self._det[t("ram_used")].setText(f"{mem.used//(1024**3)} GB")
        self._det[t("ram_free")].setText(f"{mem.available//(1024**3)} GB")
        self._det[t("disk_used")].setText(f"{s['disk_used']} GB")
        self._det[t("processes_label")].setText(str(s["processes"]))


# ═══════════════════════════════════════════════════════════════════
#  SETTINGS PAGE
# ═══════════════════════════════════════════════════════════════════
class SettingsPage(QWidget):
    def __init__(self, island=None, crosshair=None, parent=None):
        super().__init__(parent)
        self.island = island
        self.crosshair = crosshair
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._setup()
        
    def _setup(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{background:transparent;border:none;}")
        scroll.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        holder = QWidget()
        holder.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        root_layout = QVBoxLayout(holder)
        root_layout.setContentsMargins(26, 22, 30, 22)
        root_layout.setSpacing(15)
        
        # Заголовок
        title = QLabel(t("pro_features"))
        title.setStyleSheet(f"color:{TEXT_PRI};font-size:18px;font-weight:800;")
        title.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        root_layout.addWidget(title)
        
        # DYNAMIC ISLAND
        island_label = QLabel(t("dynamic_island"))
        island_label.setStyleSheet(f"color:{TEXT_PRI};font-size:14px;font-weight:700;")
        island_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        root_layout.addWidget(island_label)
        
        island_card = GlassCard((30, 26, 24, 140),12)
        island_layout = QVBoxLayout(island_card)
        island_layout.setContentsMargins(16, 12, 16, 12)
        island_layout.setSpacing(10)
        
        # Island включен/выключен
        island_check = QCheckBox(t("island_enabled"))
        island_check.setStyleSheet(f"color:{TEXT_PRI};background:transparent;")
        island_check.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        island_check.setChecked(True)
        island_check.toggled.connect(
            lambda checked: self.island.set_visible(checked) if self.island else None
        )
        island_layout.addWidget(island_check)
        
        # Анимация
        anim_check = QCheckBox(t("island_animation"))
        anim_check.setStyleSheet(f"color:{TEXT_PRI};background:transparent;")
        anim_check.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        anim_check.setChecked(True)
        anim_check.toggled.connect(
            lambda checked: self.island.set_animation(checked) if self.island else None
        )
        island_layout.addWidget(anim_check)
        
        # Размер
        size_label = QLabel(f"{t('island_size')}: 100%")
        size_label.setStyleSheet(f"color:{TEXT_MUT};font-size:10px;")
        size_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        island_layout.addWidget(size_label)
        
        size_slider = QSlider(Qt.Orientation.Horizontal)
        size_slider.setMinimum(50)
        size_slider.setMaximum(200)
        size_slider.setValue(100)
        size_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{background:rgba(217,199,168,0.15);height:4px;border-radius:2px;}}
            QSlider::handle:horizontal {{background:{ACCENT};width:16px;margin:-6px 0;border-radius:8px;}}
        """)
        size_slider.sliderMoved.connect(lambda v: (
            self.island.set_size(v / 100.0) if self.island else None,
            size_label.setText(f"{t('island_size')}: {v}%")
        ))
        island_layout.addWidget(size_slider)
        
        # Показ FPS/PING/Music
        fps_check = QCheckBox(t("show_fps"))
        fps_check.setStyleSheet(f"color:{TEXT_PRI};background:transparent;")
        fps_check.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        fps_check.setChecked(True)
        fps_check.toggled.connect(
            lambda checked: self.island.set_show_fps(checked) if self.island else None
        )
        island_layout.addWidget(fps_check)
        
        ping_check = QCheckBox(t("show_ping"))
        ping_check.setStyleSheet(f"color:{TEXT_PRI};background:transparent;")
        ping_check.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        ping_check.setChecked(True)
        ping_check.toggled.connect(
            lambda checked: self.island.set_show_ping(checked) if self.island else None
        )
        island_layout.addWidget(ping_check)
        
        music_check = QCheckBox(t("show_music"))
        music_check.setStyleSheet(f"color:{TEXT_PRI};background:transparent;")
        music_check.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        music_check.setChecked(True)
        music_check.toggled.connect(
            lambda checked: self.island.set_show_music(checked) if self.island else None
        )
        island_layout.addWidget(music_check)
        
        root_layout.addWidget(island_card)
        
        # CROSSHAIR
        cross_label = QLabel(t("crosshair"))
        cross_label.setStyleSheet(f"color:{TEXT_PRI};font-size:14px;font-weight:700;")
        cross_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        root_layout.addWidget(cross_label)
        
        cross_card = GlassCard((30, 26, 24, 140),12)
        cross_layout = QVBoxLayout(cross_card)
        cross_layout.setContentsMargins(16, 12, 16, 12)
        cross_layout.setSpacing(10)
        
        # Crosshair включен/выключен
        cross_check = QCheckBox(t("crosshair_enabled"))
        cross_check.setStyleSheet(f"color:{TEXT_PRI};background:transparent;")
        cross_check.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        cross_check.setChecked(True)
        cross_check.toggled.connect(
            lambda checked: self.crosshair.set_visible(checked) if self.crosshair else None
        )
        cross_layout.addWidget(cross_check)

        # Зазор (gap) — без верхнего ограничения по сути (большой диапазон)
        cross_gap_label = QLabel("Зазор: 5px")
        cross_gap_label.setStyleSheet(f"color:{TEXT_MUT};font-size:10px;")
        cross_gap_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        cross_layout.addWidget(cross_gap_label)

        cross_gap_slider = QSlider(Qt.Orientation.Horizontal)
        cross_gap_slider.setMinimum(0)
        cross_gap_slider.setMaximum(500)
        cross_gap_slider.setValue(5)
        cross_gap_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{background:rgba(217,199,168,0.15);height:4px;border-radius:2px;}}
            QSlider::handle:horizontal {{background:{ACCENT};width:16px;margin:-6px 0;border-radius:8px;}}
        """)
        cross_gap_slider.valueChanged.connect(lambda v: (
            self.crosshair.set_gap(v) if self.crosshair else None,
            cross_gap_label.setText(f"Зазор: {v}px")
        ))
        cross_layout.addWidget(cross_gap_slider)

        # Толщина плеча
        cross_thick_label = QLabel("Толщина: 7px")
        cross_thick_label.setStyleSheet(f"color:{TEXT_MUT};font-size:10px;")
        cross_thick_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        cross_layout.addWidget(cross_thick_label)

        cross_thick_slider = QSlider(Qt.Orientation.Horizontal)
        cross_thick_slider.setMinimum(1)
        cross_thick_slider.setMaximum(200)
        cross_thick_slider.setValue(7)
        cross_thick_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{background:rgba(217,199,168,0.15);height:4px;border-radius:2px;}}
            QSlider::handle:horizontal {{background:{ACCENT};width:16px;margin:-6px 0;border-radius:8px;}}
        """)
        cross_thick_slider.valueChanged.connect(lambda v: (
            self.crosshair.set_thickness(v) if self.crosshair else None,
            cross_thick_label.setText(f"Толщина: {v}px")
        ))
        cross_layout.addWidget(cross_thick_slider)

        # Длина плеча
        cross_len_label = QLabel("Длина: 22px")
        cross_len_label.setStyleSheet(f"color:{TEXT_MUT};font-size:10px;")
        cross_len_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        cross_layout.addWidget(cross_len_label)

        cross_len_slider = QSlider(Qt.Orientation.Horizontal)
        cross_len_slider.setMinimum(1)
        cross_len_slider.setMaximum(500)
        cross_len_slider.setValue(22)
        cross_len_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{background:rgba(217,199,168,0.15);height:4px;border-radius:2px;}}
            QSlider::handle:horizontal {{background:{ACCENT};width:16px;margin:-6px 0;border-radius:8px;}}
        """)
        cross_len_slider.valueChanged.connect(lambda v: (
            self.crosshair.set_length(v) if self.crosshair else None,
            cross_len_label.setText(f"Длина: {v}px")
        ))
        cross_layout.addWidget(cross_len_slider)

        # Прозрачность
        cross_opacity_label = QLabel("Прозрачность: 100%")
        cross_opacity_label.setStyleSheet(f"color:{TEXT_MUT};font-size:10px;")
        cross_opacity_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        cross_layout.addWidget(cross_opacity_label)

        cross_opacity_slider = QSlider(Qt.Orientation.Horizontal)
        cross_opacity_slider.setMinimum(0)
        cross_opacity_slider.setMaximum(100)
        cross_opacity_slider.setValue(100)
        cross_opacity_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{background:rgba(217,199,168,0.15);height:4px;border-radius:2px;}}
            QSlider::handle:horizontal {{background:{ACCENT};width:16px;margin:-6px 0;border-radius:8px;}}
        """)
        cross_opacity_slider.valueChanged.connect(lambda v: (
            self.crosshair.set_opacity(v) if self.crosshair else None,
            cross_opacity_label.setText(f"Прозрачность: {v}%")
        ))
        cross_layout.addWidget(cross_opacity_slider)
        
        # Цвет
        color_btn = QPushButton(t("crosshair_color"))
        color_btn.setStyleSheet(f"""
            QPushButton{{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 rgba(230,215,188,32), stop:1 rgba(200,182,148,14));
                border: 1px solid rgba(217,199,168,70);
                color:{TEXT_PRI};
                border-radius:10px;
                padding:8px 16px;
                font-family:'{FONT_FAMILY}';
                font-size:10px;
                font-weight:600;
            }}
            QPushButton:hover{{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 rgba(240,228,205,55), stop:1 rgba(210,192,160,28));
                border: 1px solid rgba(217,199,168,120);
            }}
            QPushButton:pressed{{
                background: rgba(217,199,168,12);
            }}
        """)
        color_btn.clicked.connect(lambda: self._pick_color())
        cross_layout.addWidget(color_btn)
        
        # Анимация
        anim_label = QLabel(t("crosshair_animation"))
        anim_label.setStyleSheet(f"color:{TEXT_MUT};font-size:10px;")
        anim_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        cross_layout.addWidget(anim_label)
        
        anim_combo = QComboBox()
        anim_combo.addItems(["Star Twinkle", "Выключить"])
        anim_combo.setMaximumWidth(160)
        anim_combo.setStyleSheet(f"""
            QComboBox{{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 rgba(230,215,188,30), stop:1 rgba(200,182,148,12));
                border:1px solid rgba(217,199,168,65);
                color:{TEXT_PRI};
                border-radius:8px;
                padding:5px 10px;
                font-family:'{FONT_FAMILY}';
                font-size:10px;
            }}
            QComboBox:hover{{
                border:1px solid rgba(217,199,168,120);
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 rgba(240,228,205,50), stop:1 rgba(210,192,160,22));
            }}
            QComboBox::drop-down{{border:none;width:20px;}}
            QComboBox QAbstractItemView{{
                background: rgba(30,25,20,230);
                border:1px solid rgba(217,199,168,60);
                color:{TEXT_PRI};
                selection-background-color: rgba(217,199,168,40);
                border-radius:6px;
            }}
        """)
        anim_combo.currentIndexChanged.connect(lambda i: self._set_crosshair_animation(i))
        cross_layout.addWidget(anim_combo)
        
        root_layout.addWidget(cross_card)
        
        # МУЗЫКА
        music_label = QLabel(t("music_label"))
        music_label.setStyleSheet(f"color:{TEXT_PRI};font-size:14px;font-weight:700;")
        music_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        root_layout.addWidget(music_label)
        
        music_controller = MusicController()
        root_layout.addWidget(music_controller)

        # ВНЕШНИЙ ВИД
        appearance_label = QLabel(t("appearance"))
        appearance_label.setStyleSheet(f"color:{TEXT_PRI};font-size:14px;font-weight:700;")
        appearance_label.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        root_layout.addWidget(appearance_label)

        appearance_desc = QLabel(t("appearance_desc"))
        appearance_desc.setWordWrap(True)
        appearance_desc.setStyleSheet(f"color:{TEXT_MUT};font-size:10px;")
        appearance_desc.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        root_layout.addWidget(appearance_desc)

        appearance_card = GlassCard((30, 26, 24, 140), 12)
        appearance_layout = QVBoxLayout(appearance_card)
        appearance_layout.setContentsMargins(16, 14, 16, 14)
        appearance_layout.setSpacing(12)

        self._pending_colors = {
            "accent_color": APP_SETTINGS.get("accent_color", ACCENT),
            "bg_tint_color": APP_SETTINGS.get("bg_tint_color", BG_TINT_COLOR),
            "glow_color": APP_SETTINGS.get("glow_color", GLOW_COLOR),
        }

        for key, label_key, desc_key in [
            ("accent_color", "accent_color", "accent_color_desc"),
            ("bg_tint_color", "bg_tint_color", "bg_tint_color_desc"),
            ("glow_color", "glow_color", "glow_color_desc"),
        ]:
            row = QWidget()
            row.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            row_l = QHBoxLayout(row)
            row_l.setContentsMargins(0, 0, 0, 0)
            row_l.setSpacing(12)

            tcol = QWidget()
            tcol.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            tcol_l = QVBoxLayout(tcol)
            tcol_l.setContentsMargins(0, 0, 0, 0)
            tcol_l.setSpacing(2)
            lbl = QLabel(t(label_key))
            lbl.setStyleSheet(f"color:{TEXT_PRI};font-size:12px;font-weight:700;background:transparent;")
            desc = QLabel(t(desc_key))
            desc.setWordWrap(True)
            desc.setStyleSheet(f"color:{TEXT_MUT};font-size:9px;background:transparent;")
            tcol_l.addWidget(lbl)
            tcol_l.addWidget(desc)
            row_l.addWidget(tcol, 1)

            swatch = QPushButton()
            swatch.setFixedSize(34, 28)
            swatch.setCursor(Qt.CursorShape.PointingHandCursor)
            swatch.setStyleSheet(
                f"QPushButton{{background:{self._pending_colors[key]};"
                f"border:1px solid rgba(217,199,168,90);border-radius:6px;}}"
            )
            swatch.clicked.connect(lambda _=False, k=key, sw=swatch: self._pick_theme_color(k, sw))
            row_l.addWidget(swatch)

            appearance_layout.addWidget(row)

        btn_row = QWidget()
        btn_row.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        btn_l = QHBoxLayout(btn_row)
        btn_l.setContentsMargins(0, 4, 0, 0)
        btn_l.setSpacing(10)

        reset_btn = QPushButton(t("reset_colors"))
        reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        reset_btn.setFixedHeight(34)
        reset_btn.setStyleSheet(f"""
            QPushButton{{background:rgba(217,199,168,0.08);color:{TEXT_MUT};
                border:1px solid rgba(217,199,168,60);border-radius:8px;
                font-size:11px;font-weight:700;padding:0 16px;}}
            QPushButton:hover{{background:rgba(217,199,168,0.16);color:{TEXT_PRI};}}
        """)
        reset_btn.clicked.connect(self._reset_theme_colors)
        btn_l.addWidget(reset_btn)

        apply_btn = QPushButton(t("apply_restart"))
        apply_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        apply_btn.setFixedHeight(34)
        apply_btn.setStyleSheet(f"""
            QPushButton{{background:{ACCENT};color:#1a1612;
                border:none;border-radius:8px;font-size:11px;font-weight:800;
                letter-spacing:1px;padding:0 18px;}}
            QPushButton:hover{{background:{ACCENT2};}}
        """)
        apply_btn.clicked.connect(self._apply_theme_and_restart)
        btn_l.addWidget(apply_btn)
        btn_l.addStretch()

        appearance_layout.addWidget(btn_row)

        notice = QLabel(t("restart_notice"))
        notice.setWordWrap(True)
        notice.setStyleSheet(f"color:{TEXT_DIM};font-size:9px;")
        notice.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        appearance_layout.addWidget(notice)

        root_layout.addWidget(appearance_card)

        root_layout.addStretch()

        scroll.setWidget(holder)
        outer.addWidget(scroll, 1)

    def _pick_theme_color(self, key, swatch):
        current = QColor(self._pending_colors.get(key, ACCENT))
        color = QColorDialog.getColor(current, self)
        if color.isValid():
            hexcol = color.name()
            self._pending_colors[key] = hexcol
            swatch.setStyleSheet(
                f"QPushButton{{background:{hexcol};"
                f"border:1px solid rgba(217,199,168,90);border-radius:6px;}}"
            )

    def _reset_theme_colors(self):
        defaults = {
            "accent_color": DEFAULT_SETTINGS["accent_color"],
            "bg_tint_color": DEFAULT_SETTINGS["bg_tint_color"],
            "glow_color": DEFAULT_SETTINGS["glow_color"],
        }
        save_app_settings(defaults)
        self._restart_app()

    def _apply_theme_and_restart(self):
        save_app_settings(self._pending_colors)
        self._restart_app()

    @staticmethod
    def _restart_app():
        try:
            script_path = os.path.abspath(__file__)
            subprocess.Popen(
                [sys.executable] + sys.argv,
                creationflags=(subprocess.CREATE_NEW_CONSOLE
                               if sys.platform == "win32" else 0)
            )
        except Exception:
            pass
        os._exit(0)
    def _pick_color(self):
        if self.crosshair:
            color = QColorDialog.getColor(QColor(ACCENT), self)
            if color.isValid():
                self.crosshair.set_color(color)
                
    def _set_crosshair_animation(self, index):
        if self.crosshair:
            anim_types = [
                CustomCrosshair.AnimationType.STAR_TWINKLE,
                CustomCrosshair.AnimationType.NONE,
            ]
            if index < len(anim_types):
                self.crosshair.set_animation(anim_types[index])


# ═══════════════════════════════════════════════════════════════════
#  TOOLS PAGE — отдельные переключатели системных твиков
# ═══════════════════════════════════════════════════════════════════
class ToolsPage(QWidget):
    """
    4 независимых тумблера поверх SystemTweaks. Каждый применяется
    (apply) при включении и откатывается (revert) при выключении —
    в отличие от общего Game Boost, где твики применяются разово
    и без отслеживания состояния.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._setup()

    def _setup(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 22)
        root.setSpacing(15)

        title = QLabel(t("tools_title"))
        title.setStyleSheet(f"color:{TEXT_PRI};font-size:18px;font-weight:800;")
        title.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        root.addWidget(title)

        desc = QLabel(t("tools_desc"))
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{TEXT_MUT};font-size:11px;")
        desc.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        root.addWidget(desc)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{background:transparent;border:none;}")
        scroll.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        holder = QWidget()
        holder.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        hl = QVBoxLayout(holder)
        hl.setContentsMargins(0, 0, 8, 0)
        hl.setSpacing(12)

        self._items = []
        specs = [
            ("tool_core_parking", "tool_core_parking_desc",
             SystemTweaks.core_parking_disable, SystemTweaks.core_parking_enable,
             False),
            ("tool_usb_polling", "tool_usb_polling_desc",
             SystemTweaks.usb_polling_boost, SystemTweaks.usb_polling_revert,
             False),
            ("tool_game_bar", "tool_game_bar_desc",
             SystemTweaks.game_bar_disable, SystemTweaks.game_bar_enable,
             SystemTweaks.game_bar_is_disabled()),
            ("tool_process_priority", "tool_process_priority_desc",
             SystemTweaks.process_priority_apply, SystemTweaks.process_priority_revert,
             False),
        ]
        for title_key, desc_key, apply_fn, revert_fn, initial in specs:
            hl.addWidget(self._make_tweak_card(title_key, desc_key, apply_fn, revert_fn, initial))

        hl.addStretch()
        scroll.setWidget(holder)
        root.addWidget(scroll, 1)

    def _make_tweak_card(self, title_key, desc_key, apply_fn, revert_fn, initial):
        card = GlassCard((30, 26, 24, 140), 12)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(6)

        check = QCheckBox(t(title_key))
        check.setStyleSheet(f"color:{TEXT_PRI};background:transparent;font-weight:700;font-size:12px;")
        check.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        check.setChecked(bool(initial))
        cl.addWidget(check)

        desc = QLabel(t(desc_key))
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{TEXT_MUT};font-size:10px;")
        desc.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        cl.addWidget(desc)

        status = QLabel(f"● {t('status_on') if initial else t('status_off')}")
        status.setStyleSheet(
            f"color:{SUCCESS if initial else TEXT_DIM};font-size:9px;font-weight:600;")
        status.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        cl.addWidget(status)

        def _on_toggle(checked, status=status, apply_fn=apply_fn, revert_fn=revert_fn):
            try:
                if checked:
                    apply_fn()
                else:
                    revert_fn()
            except Exception:
                pass
            status.setText(f"● {t('status_on') if checked else t('status_off')}")
            status.setStyleSheet(
                f"color:{SUCCESS if checked else TEXT_DIM};font-size:9px;font-weight:600;")

        check.toggled.connect(_on_toggle)
        self._items.append((check, apply_fn, revert_fn))
        return card


# ═══════════════════════════════════════════════════════════════════
#  CLEANUP PAGE
# ═══════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════
#  OPTIMIZATION OVERLAY  — бежевое блюр-окно поверх всего
# ═══════════════════════════════════════════════════════════════════
class OptimizationOverlay(QWidget):
    """Полноэкранный overlay с прогрессом оптимизации."""
    closed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._progress   = 0
        self._steps      = []
        self._done_steps = []
        self._current    = ""
        self._tick       = 0

        screen = QApplication.primaryScreen().geometry()
        self.setGeometry(screen)

        self._anim_timer = QTimer(self)
        self._anim_timer.timeout.connect(self._anim_tick)
        self._anim_timer.start(30)

    def set_progress(self, pct, step_text):
        self._progress = pct
        self._current  = step_text
        self.update()

    def add_done(self, text):
        self._done_steps.append(text)
        self.update()

    def _anim_tick(self):
        self._tick = (self._tick + 1) % 3600
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        w, h = self.width(), self.height()

        # Тёмный полупрозрачный фон
        p.fillRect(0, 0, w, h, QColor(10, 8, 6, 210))

        # Центральная карточка
        cw, ch = 560, 420
        cx, cy = (w - cw) // 2, (h - ch) // 2

        card = QPainterPath()
        card.addRoundedRect(cx, cy, cw, ch, 22, 22)

        # Бежевый glass fill
        bg = QLinearGradient(cx, cy, cx, cy + ch)
        bg.setColorAt(0.0, QColor(55, 46, 34, 230))
        bg.setColorAt(0.5, QColor(38, 30, 20, 240))
        bg.setColorAt(1.0, QColor(28, 22, 14, 235))
        p.fillPath(card, bg)

        # Верхний sheen
        sheen = QPainterPath()
        sheen.addRoundedRect(cx+1, cy+1, cw-2, ch//3, 21, 21)
        sg = QLinearGradient(cx, cy, cx, cy + ch//3)
        sg.setColorAt(0, QColor(255, 245, 220, 40))
        sg.setColorAt(1, QColor(255, 245, 220, 0))
        p.fillPath(sheen, sg)

        # Пульсирующая бежевая рамка
        pulse = 0.55 + 0.45 * abs(math.sin(math.radians(self._tick * 1.5)))
        border_col = QColor(217, 199, 168, int(140 * pulse))
        p.setPen(QPen(border_col, 1.8))
        p.drawPath(card)

        # Заголовок
        p.setPen(QColor(255, 248, 235))
        p.setFont(_font(22, QFont.Weight.Black))
        p.drawText(QRect(cx, cy + 28, cw, 34), Qt.AlignmentFlag.AlignCenter, "ОПТИМИЗАЦИЯ")

        p.setPen(QColor(180, 162, 132))
        p.setFont(_font(10, QFont.Weight.DemiBold))
        p.drawText(QRect(cx, cy + 62, cw, 18), Qt.AlignmentFlag.AlignCenter, "ZEUS MIDNIGHT  ·  FPS BOOST MODE")

        # Разделитель
        div_y = cy + 88
        dg = QLinearGradient(cx + 30, div_y, cx + cw - 30, div_y)
        dg.setColorAt(0, QColor(217, 199, 168, 0))
        dg.setColorAt(0.5, QColor(217, 199, 168, 90))
        dg.setColorAt(1, QColor(217, 199, 168, 0))
        p.setPen(QPen(dg, 1))
        p.drawLine(cx + 30, div_y, cx + cw - 30, div_y)

        # Выполненные шаги
        step_y = cy + 102
        for i, step in enumerate(self._done_steps[-6:]):
            p.setPen(QColor(140, 210, 140))
            p.setFont(_font(9, QFont.Weight.Bold))
            p.drawText(cx + 36, step_y + i * 22, "✓")
            p.setPen(QColor(210, 200, 185))
            p.setFont(_font(10))
            p.drawText(cx + 56, step_y + i * 22, cw - 80, 20, 0, step)

        # Текущий шаг (мерцает)
        if self._current:
            dot_a = int(200 * (0.5 + 0.5 * abs(math.sin(math.radians(self._tick * 4)))))
            p.setPen(QColor(217, 199, 168, dot_a))
            p.setFont(_font(10, QFont.Weight.Bold))
            cur_y = step_y + len(self._done_steps[-6:]) * 22 + 6
            p.drawText(cx + 36, cur_y, "▶")
            p.setPen(QColor(255, 248, 230))
            p.setFont(_font(10, QFont.Weight.Bold))
            p.drawText(cx + 56, cur_y, cw - 80, 20, 0, self._current)

        # Прогресс-бар
        bar_y = cy + ch - 72
        bar_x = cx + 36
        bar_w = cw - 72
        bar_h = 8

        # Фон бара
        bar_bg = QPainterPath()
        bar_bg.addRoundedRect(bar_x, bar_y, bar_w, bar_h, 4, 4)
        p.fillPath(bar_bg, QColor(217, 199, 168, 25))

        # Заполнение
        if self._progress > 0:
            fill_w = int(bar_w * self._progress / 100)
            bar_fill = QPainterPath()
            bar_fill.addRoundedRect(bar_x, bar_y, fill_w, bar_h, 4, 4)
            gfill = QLinearGradient(bar_x, bar_y, bar_x + fill_w, bar_y)
            gfill.setColorAt(0, QColor(217, 199, 168, 180))
            gfill.setColorAt(0.6, QColor(240, 224, 192, 220))
            gfill.setColorAt(1, QColor(255, 245, 215, 255))
            p.fillPath(bar_fill, gfill)

            # Блик на баре
            bar_sheen = QPainterPath()
            bar_sheen.addRoundedRect(bar_x, bar_y, fill_w, bar_h // 2, 4, 4)
            p.fillPath(bar_sheen, QColor(255, 255, 255, 35))

        # Процент
        p.setPen(QColor(255, 248, 230))
        p.setFont(_font(13, QFont.Weight.ExtraBold))
        p.drawText(QRect(cx, bar_y + 14, cw, 24), Qt.AlignmentFlag.AlignCenter,
                   f"{self._progress}%")

        if self._progress >= 100:
            p.setPen(QColor(140, 220, 140))
            p.setFont(_font(11, QFont.Weight.Bold))
            p.drawText(QRect(cx, bar_y + 38, cw, 20), Qt.AlignmentFlag.AlignCenter,
                       "Готово! Нажмите куда угодно чтобы закрыть")

    def mousePressEvent(self, e):
        if self._progress >= 100:
            self._anim_timer.stop()
            self.hide()
            self.closed.emit()


class SystemTweaks:
    """
    Отдельные системные твики с парами apply()/revert() — каждый может
    включаться и выключаться независимо (используется и страницей
    «Инструменты» с тумблерами, и общим Game Boost).

    Важно по-честному: некоторые твики применяются только к ТЕКУЩЕМУ
    процессу (самому Zeus Midnight), а не к играм — это отмечено в
    докстрингах и в подписях UI, чтобы не вводить в заблуждение.
    """

    # ── приоритет процесса (только для этого приложения) ───────────
    @staticmethod
    def process_priority_apply():
        """HIGH priority для процесса Zeus Midnight (не для игр —
        ОС не даёт стороннему приложению легально менять приоритет
        чужого процесса без админ-прав и явного указания целевого PID)."""
        if sys.platform != 'win32': return
        try:
            handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, os.getpid())
            ctypes.windll.kernel32.SetPriorityClass(handle, 0x00000080)  # HIGH_PRIORITY_CLASS
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass

    @staticmethod
    def process_priority_revert():
        """Возврат к NORMAL priority."""
        if sys.platform != 'win32': return
        try:
            handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, os.getpid())
            ctypes.windll.kernel32.SetPriorityClass(handle, 0x00000020)  # NORMAL_PRIORITY_CLASS
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass

    # ── Xbox Game Bar overlay ───────────────────────────────────────
    @staticmethod
    def game_bar_disable():
        if sys.platform != 'win32': return
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "AppCaptureEnabled", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except Exception:
            pass
        try:
            key2 = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"System\GameConfigStore",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key2, "GameDVR_Enabled", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key2)
        except Exception:
            pass

    @staticmethod
    def game_bar_enable():
        """Возвращает Game Bar в исходное состояние (включено по умолчанию в Windows)."""
        if sys.platform != 'win32': return
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "AppCaptureEnabled", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass
        try:
            key2 = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"System\GameConfigStore",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key2, "GameDVR_Enabled", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key2)
        except Exception:
            pass

    @staticmethod
    def game_bar_is_disabled():
        """Текущее состояние из реестра (для отображения тумблера при запуске)."""
        if sys.platform != 'win32': return False
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
                0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "AppCaptureEnabled")
            winreg.CloseKey(key)
            return val == 0
        except Exception:
            return False

    # ── CPU core parking ─────────────────────────────────────────
    # SUB_PROCESSOR GUID = 54533251-82be-4824-96c1-47b60b740d00
    # CPMINCORES (мин. % активных ядер) = 0cc5b647-c1df-4637-891a-dec35c318583
    _SUB_PROCESSOR = '54533251-82be-4824-96c1-47b60b740d00'
    _CPMINCORES    = '0cc5b647-c1df-4637-891a-dec35c318583'

    @staticmethod
    def core_parking_disable():
        """Минимум активных ядер = 100% — ядра перестают «засыпать»,
        убирается задержка их пробуждения под резкой нагрузкой."""
        if sys.platform != 'win32': return
        try:
            for flag in ('/setacvalueindex', '/setdcvalueindex'):
                subprocess.run(
                    ['powercfg', flag, 'SCHEME_CURRENT',
                     SystemTweaks._SUB_PROCESSOR, SystemTweaks._CPMINCORES, '100'],
                    capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(['powercfg', '/setactive', 'SCHEME_CURRENT'],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    @staticmethod
    def core_parking_enable():
        """Возврат к значению Windows по умолчанию (5% мин. активных ядер)."""
        if sys.platform != 'win32': return
        try:
            for flag in ('/setacvalueindex', '/setdcvalueindex'):
                subprocess.run(
                    ['powercfg', flag, 'SCHEME_CURRENT',
                     SystemTweaks._SUB_PROCESSOR, SystemTweaks._CPMINCORES, '5'],
                    capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(['powercfg', '/setactive', 'SCHEME_CURRENT'],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    # ── USB Selective Suspend (HID polling latency) ─────────────────
    # SUB_USB GUID = 2a737441-1930-4402-8d77-b2bebba308a3
    # USBSELECTIVESUSPEND = 48e6b7a6-50f5-4782-a5d4-53bb8f07e226
    _SUB_USB = '2a737441-1930-4402-8d77-b2bebba308a3'
    _USBSS   = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'

    @staticmethod
    def usb_polling_boost():
        """Отключает USB Selective Suspend — убирает программное
        усыпление USB-контроллера, которое может добавлять микро-задержку
        отклика мыши/клавиатуры. НЕ меняет физическую частоту опроса
        устройства — та задаётся прошивкой/портом."""
        if sys.platform != 'win32': return
        try:
            for flag in ('/setacvalueindex', '/setdcvalueindex'):
                subprocess.run(
                    ['powercfg', flag, 'SCHEME_CURRENT',
                     SystemTweaks._SUB_USB, SystemTweaks._USBSS, '0'],
                    capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(['powercfg', '/setactive', 'SCHEME_CURRENT'],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass

    @staticmethod
    def usb_polling_revert():
        """Возврат USB Selective Suspend к значению по умолчанию (включено)."""
        if sys.platform != 'win32': return
        try:
            for flag in ('/setacvalueindex', '/setdcvalueindex'):
                subprocess.run(
                    ['powercfg', flag, 'SCHEME_CURRENT',
                     SystemTweaks._SUB_USB, SystemTweaks._USBSS, '1'],
                    capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(['powercfg', '/setactive', 'SCHEME_CURRENT'],
                           capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════
#  REAL OPTIMIZER WORKER
# ═══════════════════════════════════════════════════════════════════
class OptimizerWorker(QThread):
    """Реальная оптимизация системы под максимальный FPS."""
    step_done    = pyqtSignal(str)     # завершённый шаг
    step_started = pyqtSignal(str)     # начатый шаг
    progress     = pyqtSignal(int)     # 0..100
    finished_all = pyqtSignal()

    def run(self):
        steps = [
            ("Повышение приоритета процесса",       self._boost_process_priority),
            ("Отключение Xbox Game Bar",             self._disable_game_bar),
            ("Очистка буфера обмена",               self._clear_clipboard),
            ("Режим высокой производительности",     self._set_high_perf_power),
            ("Очистка DNS-кэша",                    self._flush_dns),
            ("Очистка временных файлов",             self._clean_temp),
            ("Завершение ненужных процессов",        self._kill_bloat),
            ("Оптимизация таймера системы",          self._optimize_timer),
            ("Очистка рабочего набора памяти",       self._trim_memory),
            ("Приоритет GPU для игр (реестр)",       self._gpu_scheduling),
            ("Снижение сетевых задержек (мультимедиа)", self._network_throttling),
            ("Приоритет программ над фоном (CPU)",   self._foreground_priority),
            ("Отключение визуальных эффектов Windows", self._disable_visual_effects),
            ("Снижение задержки системного отклика", self._system_responsiveness),
            ("Снятие искусственного троттлинга энергосбережения", self._disable_core_parking),
            ("Повышение частоты опроса входных устройств", self._boost_input_polling),
        ]
        n = len(steps)
        for i, (name, fn) in enumerate(steps):
            self.step_started.emit(name)
            try:
                fn()
            except Exception:
                pass
            self.step_done.emit(name)
            self.progress.emit(int((i + 1) / n * 100))
            time.sleep(0.35)
        self.finished_all.emit()

    # ── реальные оптимизации ─────────────────────────────────────

    def _boost_process_priority(self):
        """Выставить HIGH priority текущему процессу."""
        SystemTweaks.process_priority_apply()

    def _disable_game_bar(self):
        """Отключить Xbox Game Bar overlay через реестр."""
        SystemTweaks.game_bar_disable()

    def _clear_clipboard(self):
        """Очистить буфер обмена."""
        if sys.platform == 'win32':
            try:
                ctypes.windll.user32.OpenClipboard(0)
                ctypes.windll.user32.EmptyClipboard()
                ctypes.windll.user32.CloseClipboard()
            except Exception:
                pass

    def _set_high_perf_power(self):
        """Выставить схему питания «Высокая производительность»."""
        if sys.platform != 'win32': return
        subprocess.run(
            ['powercfg', '/setactive', '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

    def _flush_dns(self):
        """Сбросить DNS-кэш."""
        if sys.platform != 'win32': return
        subprocess.run(['ipconfig', '/flushdns'],
                       capture_output=True,
                       creationflags=subprocess.CREATE_NO_WINDOW)

    def _clean_temp(self):
        """Удалить файлы из папки TEMP."""
        temp = os.environ.get("TEMP", "")
        if not temp or not os.path.exists(temp):
            return
        for name in os.listdir(temp):
            try:
                fp = os.path.join(temp, name)
                if os.path.isfile(fp):
                    os.remove(fp)
            except Exception:
                pass

    def _kill_bloat(self):
        """Завершить типичные фоновые процессы, мешающие FPS.
        Намеренно НЕ трогаем антивирус/защитник Windows (MsMpEng.exe) —
        отключение защиты ради FPS того не стоит."""
        BLOAT = [
            "OneDrive.exe", "Teams.exe", "Skype.exe",
            "SearchIndexer.exe",
            "SpeechRuntime.exe", "RuntimeBroker.exe",
        ]
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.info['name'] in BLOAT:
                    # мягкое завершение
                    proc.terminate()
            except Exception:
                pass

    def _optimize_timer(self):
        """Поднять разрешение системного таймера до 1мс через winmm."""
        if sys.platform != 'win32': return
        try:
            ctypes.windll.winmm.timeBeginPeriod(1)
        except Exception:
            pass

    def _trim_memory(self):
        """SetProcessWorkingSetSize — освободить неиспользуемую RAM."""
        if sys.platform != 'win32': return
        handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, os.getpid())
        ctypes.windll.kernel32.SetProcessWorkingSetSize(handle, -1, -1)
        ctypes.windll.kernel32.CloseHandle(handle)
        # Всем другим процессам тоже попробуем
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                h = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, proc.pid)
                if h:
                    ctypes.windll.kernel32.SetProcessWorkingSetSize(h, -1, -1)
                    ctypes.windll.kernel32.CloseHandle(h)
            except Exception:
                pass

    def _gpu_scheduling(self):
        """Hardware-Accelerated GPU Scheduling через реестр (требует перезагрузки)."""
        if sys.platform != 'win32': return
        import winreg
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "HwSchMode", 0, winreg.REG_DWORD, 2)
            winreg.CloseKey(key)
        except Exception:
            pass

    def _network_throttling(self):
        """Снять системное ограничение полосы для мультимедиа/сетевых пакетов
        (NetworkThrottlingIndex) — известная и безопасная игровая настройка,
        снижает джиттер/пинг под нагрузкой."""
        if sys.platform != 'win32': return
        import winreg
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "NetworkThrottlingIndex", 0, winreg.REG_DWORD, 0xFFFFFFFF)
            winreg.CloseKey(key)
        except Exception:
            pass

    def _foreground_priority(self):
        """Отдать больше процессорного времени активному (переднему) приложению,
        а не фоновым службам — Win32PrioritySeparation."""
        if sys.platform != 'win32': return
        import winreg
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\PriorityControl",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "Win32PrioritySeparation", 0, winreg.REG_DWORD, 38)
            winreg.CloseKey(key)
        except Exception:
            pass

    def _disable_visual_effects(self):
        """Отключить часть UI-анимаций Windows (SPI_SETUIEFFECTS) —
        мелочь, но снижает фоновую нагрузку на отрисовку рабочего стола."""
        if sys.platform != 'win32': return
        try:
            SPI_SETUIEFFECTS = 0x103F
            ctypes.windll.user32.SystemParametersInfoW(SPI_SETUIEFFECTS, 0, None, 0)
        except Exception:
            pass

    def _system_responsiveness(self):
        """SystemResponsiveness=0 — рекомендация Microsoft для систем,
        где приоритет важнее мультимедийного резервирования CPU для служб."""
        if sys.platform != 'win32': return
        import winreg
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "SystemResponsiveness", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except Exception:
            pass

    def _disable_core_parking(self):
        """Отключает CPU Core Parking в активном плане питания (см. SystemTweaks)."""
        SystemTweaks.core_parking_disable()

    def _boost_input_polling(self):
        """Снижает HID-задержку: отключает USB Selective Suspend (см. SystemTweaks)."""
        SystemTweaks.usb_polling_boost()


# ═══════════════════════════════════════════════════════════════════
#  CLEANUP PAGE
# ═══════════════════════════════════════════════════════════════════
class CleanupPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._scanning = False
        self._setup()

    def _setup(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 22)
        root.setSpacing(14)

        root.addWidget(_tl(t("cleanup"), f"color:{TEXT_PRI};font-size:17px;font-weight:800;"))

        status_card = GlassCard((30, 26, 24, 145), 14)
        sl = QVBoxLayout(status_card)
        sl.setContentsMargins(24, 20, 24, 20)
        sl.setSpacing(10)
        self._status_lbl = _tl("Готово к сканированию", f"color:{TEXT_MUT};font-size:13px;")
        sl.addWidget(self._status_lbl)
        self._found_lbl = _tl("0 МБ найдено", f"color:{TEXT_PRI};font-size:26px;font-weight:800;")
        sl.addWidget(self._found_lbl)
        btn_row = QHBoxLayout()
        self._scan_btn = GlowButton(t("cleanup_btn"), "gold")
        self._scan_btn.setFixedWidth(200)
        self._scan_btn.clicked.connect(self._run_scan)
        btn_row.addWidget(self._scan_btn)
        self._del_btn = GlowButton("УДАЛИТЬ", "ghost")
        self._del_btn.setFixedWidth(160)
        self._del_btn.setEnabled(False)
        self._del_btn.clicked.connect(self._run_delete)
        btn_row.addWidget(self._del_btn)
        btn_row.addStretch()
        sl.addLayout(btn_row)
        root.addWidget(status_card)

        targets_card = GlassCard((30, 26, 24, 140), 12)
        tl2 = QVBoxLayout(targets_card)
        tl2.setContentsMargins(18, 14, 18, 14)
        tl2.setSpacing(6)
        tl2.addWidget(_tl("Что сканируется:", f"color:{TEXT_PRI};font-size:12px;font-weight:700;"))

        self._targets_info = {
            "Временные файлы Windows (%TEMP%)": "",
            "Системный мусор (Windows\\Temp)":  "",
            "Кэш обновлений (SoftwareDistribution)": "",
            "Prefetch-файлы": "",
        }
        self._target_labels = {}
        for name in self._targets_info:
            row = QWidget()
            row.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            rl.setSpacing(8)
            rl.addWidget(_tl("◆", f"color:{ACCENT};font-size:8px;"))
            rl.addWidget(_tl(name, f"color:{TEXT_PRI};font-size:10px;"))
            rl.addStretch()
            size_lbl = _tl("—", f"color:{TEXT_MUT};font-size:10px;")
            rl.addWidget(size_lbl)
            self._target_labels[name] = size_lbl
            tl2.addWidget(row)

        root.addWidget(targets_card)
        root.addStretch()

    def _run_scan(self):
        if self._scanning: return
        self._scanning = True
        self._status_lbl.setText("Сканирование...")
        self._scan_btn.setEnabled(False)
        self._del_btn.setEnabled(False)
        self._worker = CleanupWorker()
        self._worker.result.connect(self._on_result)
        self._worker.start()

    def _on_result(self, data):
        self._scanning = False
        self._last_data = data
        total = sum(data.values())
        self._found_lbl.setText(f"{total} МБ найдено")
        self._status_lbl.setText("Сканирование завершено")
        self._scan_btn.setEnabled(True)
        if total > 0:
            self._del_btn.setEnabled(True)
        for name, mb in data.items():
            if name in self._target_labels:
                self._target_labels[name].setText(f"{mb} МБ" if mb > 0 else "0 МБ")

    def _run_delete(self):
        self._status_lbl.setText("Удаление...")
        self._del_btn.setEnabled(False)
        self._del_worker = CleanupDeleteWorker()
        self._del_worker.done.connect(lambda freed: (
            self._status_lbl.setText(f"Удалено {freed} МБ"),
            self._found_lbl.setText("0 МБ"),
        ))
        self._del_worker.start()


class CleanupWorker(QThread):
    result = pyqtSignal(dict)

    PATHS = {
        "Временные файлы Windows (%TEMP%)":        lambda: os.environ.get("TEMP", ""),
        "Системный мусор (Windows\\Temp)":          lambda: r"C:\Windows\Temp",
        "Кэш обновлений (SoftwareDistribution)":   lambda: r"C:\Windows\SoftwareDistribution\Download",
        "Prefetch-файлы":                           lambda: r"C:\Windows\Prefetch",
    }

    def _dir_size_mb(self, path):
        mb = 0
        try:
            for dp, dns, fns in os.walk(path):
                for f in fns:
                    try: mb += os.path.getsize(os.path.join(dp, f))
                    except Exception: pass
        except Exception: pass
        return mb // (1024 * 1024)

    def run(self):
        data = {}
        for name, path_fn in self.PATHS.items():
            data[name] = self._dir_size_mb(path_fn())
        self.result.emit(data)


class CleanupDeleteWorker(QThread):
    done = pyqtSignal(int)

    PATHS = [
        lambda: os.environ.get("TEMP", ""),
        lambda: r"C:\Windows\Temp",
    ]

    def run(self):
        freed = 0
        for path_fn in self.PATHS:
            path = path_fn()
            try:
                for name in os.listdir(path):
                    fp = os.path.join(path, name)
                    try:
                        sz = os.path.getsize(fp)
                        os.remove(fp)
                        freed += sz
                    except Exception:
                        pass
            except Exception:
                pass
        self.done.emit(freed // (1024 * 1024))


class MonitorWorker(QThread):
    stats_updated = pyqtSignal(dict)

    def run(self):
        while not self.isInterruptionRequested():
            try:
                cpu  = psutil.cpu_percent(interval=0.5)
                mem  = psutil.virtual_memory()
                drv  = 'C:\\' if sys.platform == 'win32' else '/'
                disk = psutil.disk_usage(drv)
                up   = str(timedelta(seconds=int(time.time() - psutil.boot_time())))
                self.stats_updated.emit({
                    "cpu": cpu, "ram": mem.percent,
                    "ram_used":  mem.used   // (1024**3),
                    "ram_total": mem.total  // (1024**3),
                    "disk": disk.percent,
                    "disk_used":  disk.used  // (1024**3),
                    "disk_total": disk.total // (1024**3),
                    "uptime": up, "processes": len(psutil.pids()),
                })
            except Exception:
                pass
            time.sleep(1)


# ═══════════════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════════════
class Sidebar(QWidget):
    page_changed = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(202)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._buttons=[]
        self._setup()

    def paintEvent(self, e):
        p=QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        
        # Full glass beige background - layered for depth
        # Base warm tint
        p.fillRect(0, 0, w, h, QColor(40, 32, 22, 80))
        
        # Beige glass layer
        bg_grad = QLinearGradient(0, 0, w, h)
        bg_grad.setColorAt(0.0,  QColor(217, 199, 168, 38))
        bg_grad.setColorAt(0.4,  QColor(200, 182, 148, 22))
        bg_grad.setColorAt(1.0,  QColor(185, 165, 130, 30))
        p.fillRect(0, 0, w, h, bg_grad)
        
        # Top highlight — frosted glass sheen
        top_sheen = QLinearGradient(0, 0, 0, 120)
        top_sheen.setColorAt(0, QColor(255, 248, 235, 55))
        top_sheen.setColorAt(1, QColor(255, 248, 235, 0))
        p.fillRect(0, 0, w, 120, top_sheen)
        
        # Right border — subtle gold line
        border_grad = QLinearGradient(0, 0, 0, h)
        border_grad.setColorAt(0.0, QColor(217, 199, 168, 0))
        border_grad.setColorAt(0.25, QColor(217, 199, 168, 90))
        border_grad.setColorAt(0.75, QColor(217, 199, 168, 60))
        border_grad.setColorAt(1.0, QColor(217, 199, 168, 0))
        p.setPen(QPen(border_grad, 1))
        p.drawLine(w-1, 0, w-1, h)

    def _setup(self):
        lay=QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        lw=QWidget()
        lw.setFixedHeight(76)
        lw.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        ll=QHBoxLayout(lw)
        ll.setContentsMargins(18,0,18,0)
        # Загружаем logo.png если лежит рядом
        _logo_loaded = False
        for _lp in ["logo.png", "icon.ico"]:
            if os.path.exists(_lp):
                _px = QPixmap(_lp)
                if not _px.isNull():
                    _logo_lbl = QLabel()
                    _logo_lbl.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
                    _logo_lbl.setPixmap(_px.scaled(38, 38,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation))
                    ll.addWidget(_logo_lbl)
                    ll.addSpacing(6)
                    _logo_loaded = True
                    break
        if not _logo_loaded:
            bl=QLabel("Z")
            bl.setStyleSheet(f"color:{ACCENT};font-size:22px;font-weight:900;")
            bl.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            ll.addWidget(bl)
            ll.addSpacing(8)
        tv=QVBoxLayout()
        tv.setSpacing(0)
        t1=_tl("ZEUS",f"color:{TEXT_PRI};font:800 15px '{FONT_FAMILY}';letter-spacing:3px;")
        t2=_tl("MIDNIGHT",f"color:{TEXT_MUT};font:600 8px '{FONT_FAMILY}';letter-spacing:2.5px;")
        tv.addWidget(t1)
        tv.addWidget(t2)
        ll.addLayout(tv)
        ll.addStretch()
        lay.addWidget(lw)

        div=QFrame()
        div.setFixedHeight(1)
        div.setStyleSheet("background:rgba(217,199,168,0.1);")
        lay.addWidget(div)
        lay.addSpacing(10)

        nc=QWidget()
        nc.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        nl=QVBoxLayout(nc)
        nl.setContentsMargins(10,0,10,0)
        nl.setSpacing(3)
        for ico,nm,idx in [("◈",t("dashboard"),0),("◎",t("cleanup_page"),1),
                             ("▣",t("performance"),2),("◉",t("privacy_page"),3),
                             ("⬡",t("tools"),4),
                             ("◧",t("settings"),5)]:
            btn=NavButton(ico,nm)
            btn.clicked.connect(lambda i=idx: self._sel(i))
            self._buttons.append(btn)
            nl.addWidget(btn)
        lay.addWidget(nc)
        lay.addStretch()

        ac=QWidget()
        ac.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        al=QVBoxLayout(ac)
        al.setContentsMargins(10,0,10,14)
        d2=QFrame()
        d2.setFixedHeight(1)
        d2.setStyleSheet("background:rgba(217,199,168,0.1);")
        al.addWidget(d2)
        al.addSpacing(8)
        ab=NavButton("◦",t("about"))
        al.addWidget(ab)
        lay.addWidget(ac)
        self._sel(0)

    def _sel(self, idx):
        for i,b in enumerate(self._buttons):
            b.setActive(i==idx)
        self.page_changed.emit(idx)


# ═══════════════════════════════════════════════════════════════════
#  KEY GATE — экран ввода ключа доступа
# ═══════════════════════════════════════════════════════════════════
class KeyGateWindow(QWidget):
    """Окно входа по ключу. Показывается перед основным окном приложения.
    При успешной проверке вызывает on_success() и закрывается."""

    def __init__(self, on_success):
        super().__init__()
        self._on_success = on_success
        self.setWindowTitle("Zeus Midnight — Access")
        self.setFixedSize(420, 520)
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._drag_pos = None
        self._build_ui()

        # центрируем на экране
        screen = QApplication.primaryScreen().geometry()
        self.move(screen.center().x() - self.width() // 2,
                  screen.center().y() - self.height() // 2)

    def _build_ui(self):
        bg = BackgroundWidget(self)
        bg.setGeometry(0, 0, self.width(), self.height())

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # верхняя полоса с крестиком закрытия
        tb = QWidget()
        tb.setFixedHeight(38)
        tb.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(0, 0, 6, 0)
        tbl.addStretch()
        close_btn = QPushButton("x")
        close_btn.setFixedSize(30, 26)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setStyleSheet(f"""
            QPushButton{{background:rgba(217,199,168,0.08);border:none;
                color:{TEXT_MUT};font-size:12px;border-radius:6px;}}
            QPushButton:hover{{background:#c0392b;color:white;}}
        """)
        close_btn.clicked.connect(lambda: os._exit(0))
        tbl.addWidget(close_btn)
        root.addWidget(tb)

        root.addStretch(1)

        center = QWidget()
        center.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        cl = QVBoxLayout(center)
        cl.setContentsMargins(40, 0, 40, 0)
        cl.setSpacing(14)
        cl.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        logo = QLabel("⬡")
        logo.setStyleSheet(f"color:{ACCENT};font-size:34px;background:transparent;")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cl.addWidget(logo)

        title = QLabel(t("key_title"))
        title.setStyleSheet(f"color:{TEXT_PRI};font-size:20px;font-weight:800;"
                             f"letter-spacing:3px;background:transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cl.addWidget(title)

        subtitle = QLabel(t("key_subtitle"))
        subtitle.setStyleSheet(f"color:{TEXT_MUT};font-size:11px;background:transparent;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        cl.addWidget(subtitle)

        cl.addSpacing(10)

        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText(t("key_placeholder"))
        self.key_input.setFixedHeight(42)
        self.key_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.key_input.setStyleSheet(f"""
            QLineEdit{{
                background: rgba(217,199,168,0.06);
                border: 1px solid rgba(217,199,168,80);
                border-radius: 10px;
                color: {TEXT_PRI};
                font-size: 13px;
                font-weight: 600;
                letter-spacing: 1px;
                padding: 0 12px;
            }}
            QLineEdit:focus{{border: 1px solid {ACCENT};}}
        """)
        self.key_input.returnPressed.connect(self._try_unlock)
        cl.addWidget(self.key_input)

        self.remember_check = QCheckBox(t("key_remember"))
        self.remember_check.setStyleSheet(f"color:{TEXT_MUT};font-size:10px;background:transparent;")
        self.remember_check.setChecked(True)
        cl.addWidget(self.remember_check, alignment=Qt.AlignmentFlag.AlignHCenter)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet(f"color:{DANGER};font-size:10px;font-weight:600;background:transparent;")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cl.addWidget(self.error_label)

        self.submit_btn = QPushButton(t("key_submit"))
        self.submit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.submit_btn.setFixedHeight(44)
        self.submit_btn.setStyleSheet(f"""
            QPushButton{{
                background: {ACCENT};
                color: #1a1612;
                border: none;
                border-radius: 10px;
                font-size: 12px;
                font-weight: 800;
                letter-spacing: 2px;
            }}
            QPushButton:hover{{background: {ACCENT2};}}
            QPushButton:pressed{{background: {ACCENT3};}}
        """)
        self.submit_btn.clicked.connect(self._try_unlock)
        cl.addWidget(self.submit_btn)

        root.addWidget(center)
        root.addStretch(1)

        footer = QLabel(t("key_footer"))
        footer.setStyleSheet(f"color:{TEXT_DIM};font-size:9px;background:transparent;")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(footer)
        root.addSpacing(18)

    def _try_unlock(self):
        key = self.key_input.text().strip()
        if not key:
            self.error_label.setText(t("key_empty"))
            return
        self.submit_btn.setText(t("key_checking"))
        self.submit_btn.setEnabled(False)
        QApplication.processEvents()
        ok = validate_key(key)
        if ok:
            save_app_settings({
                "licensed": True,
                "saved_key": key.upper() if self.remember_check.isChecked() else "",
                "remember_key": self.remember_check.isChecked(),
            })
            self.close()
            self._on_success()
        else:
            self.error_label.setText(t("key_invalid"))
            self.submit_btn.setText(t("key_submit"))
            self.submit_btn.setEnabled(True)

    # ── перетаскивание окна за верхнюю полосу ───────────────────────
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and e.position().y() < 38:
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag_pos and e.buttons() == Qt.MouseButton.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, e):
        self._drag_pos = None


# ═══════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════
class ZeusMidnight(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Zeus Midnight Pro")
        self.setMinimumSize(1020,660)
        self.resize(1120,730)

        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.FramelessWindowHint
        )

        if os.path.exists("icon.ico"):
            self.setWindowIcon(QIcon("icon.ico"))

        self._drag_pos = None
        
        # Dynamic Island
        self.island = DynamicIsland()
        self.island.show()
        
        # Custom Crosshair
        self.crosshair = CustomCrosshair()
        self.crosshair.show()

        # Stats Monitor
        self.stats_monitor = StatsMonitor()
        self.stats_monitor.fps_updated.connect(lambda fps: self.island.set_fps(fps))
        self.stats_monitor.ping_updated.connect(lambda ping: self.island.set_ping(ping))
        self.stats_monitor.start()
        # Подключаем счётчик кадров — каждый тик Island = 1 кадр UI
        self.island.set_tick_callback(self.stats_monitor.count_frame)
        
        self._setup_ui()
        self._start_monitor()

    def _setup_ui(self):
        central = BackgroundWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        tb=QWidget()
        tb.setFixedHeight(46)
        tb.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        tb.setStyleSheet("background: transparent;")
        tbl=QHBoxLayout(tb)
        tbl.setContentsMargins(20,0,12,0)
        tbl.setSpacing(8)

        ver=_tl(t("version"),f"color:{TEXT_MUT};font-size:10px;letter-spacing:1px;")
        tbl.addWidget(ver)
        tbl.addStretch()

        for sym,slot in [("_", self.showMinimized),
                          ("□", self._toggle_max),
                          ("x", self.close)]:
            btn=QPushButton(sym)
            btn.setFixedSize(36,28)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            is_close = sym=="x"
            btn.setStyleSheet(f"""
                QPushButton{{background:rgba(217,199,168,0.08);border:none;
                    color:{TEXT_MUT};font-size:12px;border-radius:6px;}}
                QPushButton:hover{{background:{"#c0392b" if is_close else "rgba(217,199,168,0.2)"};
                    color:{"white" if is_close else TEXT_PRI};}}
            """)
            btn.clicked.connect(slot)
            tbl.addWidget(btn)
        root.addWidget(tb)

        sep=QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:rgba(217,199,168,0.08);")
        root.addWidget(sep)

        body=QWidget()
        body.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        body.setStyleSheet("background: transparent;")
        bl=QHBoxLayout(body)
        bl.setContentsMargins(0,0,0,0)
        bl.setSpacing(0)

        self.sidebar=Sidebar()
        self.sidebar.page_changed.connect(self._sw)
        bl.addWidget(self.sidebar)

        self.stack=QStackedWidget()
        self.stack.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.stack.setStyleSheet("background:transparent;")
        bl.addWidget(self.stack,1)
        root.addWidget(body,1)

        self.dash =DashboardPage()
        self.clean=CleanupPage()
        self.perf =PerformancePage()
        self.settings_page = SettingsPage(self.island, self.crosshair)
        self.tools_page = ToolsPage()

        self.stack.addWidget(self.dash)        # index 0
        self.stack.addWidget(self.clean)       # index 1
        self.stack.addWidget(self.perf)        # index 2

        ph = QWidget()
        ph.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        pl = QVBoxLayout(ph)
        pl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pl.addWidget(_tl(t("pro_features"), f"color:{TEXT_MUT};font-size:22px;font-weight:700;"),
                     alignment=Qt.AlignmentFlag.AlignCenter)
        pl.addWidget(_tl(t("section_dev"), f"color:{TEXT_DIM};font-size:13px;"),
                     alignment=Qt.AlignmentFlag.AlignCenter)
        self.stack.addWidget(ph)               # index 3 (privacy_page placeholder)

        self.stack.addWidget(self.tools_page)  # index 4 (real Tools page)
        self.stack.addWidget(self.settings_page)     # index 5

        self.dash.act_btns[0].clicked.connect(lambda: self._sw(1))  # Cleanup
        self.dash.act_btns[1].clicked.connect(lambda: self._sw(2))  # Performance
        self.dash.act_btns[2].clicked.connect(lambda: self._sw(3))  # Privacy
        self.dash.act_btns[3].clicked.connect(self._toggle_gaming)
        self.dash.opt_btn.clicked.connect(self._run_optimization)
        self.perf.opt_btn.clicked.connect(self._run_optimization)

    def _toggle_gaming(self):
        """Быстрый гейминг-буст (кнопка на дашборде)."""
        self._run_optimization()

    def _run_optimization(self):
        """Запустить реальную оптимизацию с overlay."""
        self._overlay = OptimizationOverlay()
        self._overlay.show()
        self._opt_worker = OptimizerWorker()
        self._opt_worker.step_started.connect(
            lambda s: self._overlay.set_progress(self._overlay._progress, s))
        self._opt_worker.step_done.connect(self._overlay.add_done)
        self._opt_worker.progress.connect(
            lambda pct: self._overlay.set_progress(pct, self._overlay._current))
        self._opt_worker.finished_all.connect(
            lambda: self._overlay.set_progress(100, "Оптимизация завершена!"))
        self._opt_worker.start()

    def _toggle_max(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _sw(self, idx):
        self.stack.setCurrentIndex(idx)
        for i,b in enumerate(self.sidebar._buttons):
            b.setActive(i==idx)

    def mousePressEvent(self, e):
        if e.button()==Qt.MouseButton.LeftButton and e.position().y()<50:
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag_pos and e.buttons()==Qt.MouseButton.LeftButton:
            self.move(e.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, e):
        self._drag_pos = None

    def _start_monitor(self):
        self._mon=MonitorWorker()
        self._mon.stats_updated.connect(self._upd)
        self._mon.start()

    def _upd(self, s):
        self.dash.update_stats(s)
        if self.stack.currentIndex()==2:
            self.perf.update_stats(s)

    def closeEvent(self, e):
        for attr in ["_mon", "stats_monitor"]:
            w = getattr(self, attr, None)
            if w and hasattr(w, 'isRunning'):
                if w.isRunning():
                    w.requestInterruption()
                    w.quit()
                    w.wait(2000)
        self.island.close()
        self.crosshair.close()
        super().closeEvent(e)


# ═══════════════════════════════════════════════════════════════════
#  HOT-RELOAD WATCHER
#  Следит за изменениями zeus_midnight.py и перезапускает процесс
# ═══════════════════════════════════════════════════════════════════
class HotReloadWatcher(QThread):
    """Следит за mtime файла скрипта и перезапускает его при изменении."""
    def __init__(self, filepath, parent=None):
        super().__init__(parent)
        self._path = filepath
        self._last_mtime = os.path.getmtime(filepath)
        self._running = True

    def run(self):
        while self._running:
            try:
                mtime = os.path.getmtime(self._path)
                if mtime != self._last_mtime:
                    self._last_mtime = mtime
                    time.sleep(0.3)   # ждём, пока редактор дозапишет
                    # Перезапускаем тот же процесс
                    subprocess.Popen(
                        [sys.executable] + sys.argv,
                        creationflags=(subprocess.CREATE_NEW_CONSOLE
                                       if sys.platform == "win32" else 0)
                    )
                    # Завершаем текущий процесс
                    os._exit(0)
            except Exception:
                pass
            time.sleep(0.8)

    def stop(self):
        self._running = False


# ═══════════════════════════════════════════════════════════════════
#  ENTRY
# ═══════════════════════════════════════════════════════════════════
def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    from PyQt6.QtGui import QPalette
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window,     QColor("#14120e"))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(TEXT_PRI))
    pal.setColor(QPalette.ColorRole.Base,       QColor("#1a1815"))
    pal.setColor(QPalette.ColorRole.Text,       QColor(TEXT_PRI))
    app.setPalette(pal)

    state = {"win": None, "reload_watcher": None}

    def _launch_main_window():
        win = ZeusMidnight()
        win.show()
        state["win"] = win

        # ── Hot-reload: только если запущен напрямую как .py ──────
        script_path = os.path.abspath(__file__)
        if script_path.endswith(".py") and os.path.exists(script_path):
            watcher = HotReloadWatcher(script_path)
            watcher.start()
            state["reload_watcher"] = watcher

    # Если ключ уже сохранён и до сих пор валиден — пропускаем экран входа
    remembered_key = APP_SETTINGS.get("saved_key", "")
    if APP_SETTINGS.get("remember_key") and remembered_key and validate_key(remembered_key):
        _launch_main_window()
    else:
        gate = KeyGateWindow(on_success=_launch_main_window)
        gate.show()
        state["win"] = gate

    exit_code = app.exec()

    watcher = state.get("reload_watcher")
    if watcher:
        watcher.stop()
        watcher.wait(1000)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()