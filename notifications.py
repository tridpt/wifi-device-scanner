"""Optional Windows notifications with a dependency-free fallback."""

from __future__ import annotations

import ctypes
import os
from typing import Any


def notify(title: str, message: str, *, duration: str = "short") -> bool:
    """Show a toast when winotify is installed; otherwise beep and return False."""
    try:
        from winotify import Notification

        toast = Notification(app_id="Wi-Fi Device Scanner", title=str(title), msg=str(message))
        toast.set_audio("Default", loop=False)
        toast.show()
        return True
    except Exception:
        pass
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBeep(0x40)
        except Exception:
            pass
    return False


def notify_changes(changes: dict[str, Any]) -> bool:
    """Format a concise new/removed/changed-device notification."""
    new_count = len(changes.get("new") or [])
    removed_count = len(changes.get("removed") or [])
    changed_count = len(changes.get("changed") or [])
    if not any((new_count, removed_count, changed_count)):
        return False
    parts = []
    if new_count:
        parts.append(f"mới {new_count}")
    if removed_count:
        parts.append(f"mất kết nối {removed_count}")
    if changed_count:
        parts.append(f"thay đổi {changed_count}")
    return notify("Thay đổi mạng Wi-Fi", "; ".join(parts) + ". Hãy mở ứng dụng để xem bằng chứng.")


__all__ = ["notify", "notify_changes"]
