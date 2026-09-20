from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pyray as rl

from openpilot.system.ui.lib.application import gui_app, FontWeight, TextAlignment
from openpilot.system.ui.widgets import Widget
from openpilot.system.ui.widgets.button import Button, ButtonStyle
from openpilot.system.ui.widgets.label import Label

TOOL_PATH = Path(os.getenv("TSS3_ORACLE_TOOL", "/data/tss3-oracle/tss3-unified-signer"))
RUN_ROOT = Path(os.getenv("TSS3_ORACLE_RUN_ROOT", "/data/tss3-oracle-runs"))
STATUS_SCHEMA = "camry-f33-oracle-ui-status-v1"

_oracle_bringup_visible = False


def oracle_bringup_visible() -> bool:
  return _oracle_bringup_visible


BACKGROUND = rl.Color(20, 20, 20, 255)
CARD = rl.Color(36, 36, 36, 255)
TEXT = rl.Color(238, 238, 238, 255)
MUTED = rl.Color(145, 145, 145, 255)
ACTIVE = rl.Color(91, 111, 255, 255)
DONE = rl.Color(60, 180, 90, 255)
ERROR = rl.Color(226, 44, 44, 255)

STEPS = (
  "Catch EPS startup",
  "Install RAM oracle",
  "Vehicle READY / Park",
  "Restart Brake / EPB",
  "Restart FRC",
  "Verify DRCC + oracle",
)

STAGE_STEP = {
  "arming": 0,
  "armed": 0,
  "programming": 1,
  "waiting_ready": 2,
  "ready_for_brake": 3,
  "restarting_brake": 3,
  "brake_complete": 4,
  "restarting_frc": 4,
  "frc_complete": 5,
  "verifying": 5,
  "done": len(STEPS),
}


def tool_available() -> bool:
  return TOOL_PATH.is_file() and os.access(TOOL_PATH, os.X_OK)


class Tss3OracleBringupDialog(Widget):
  def __init__(self):
    super().__init__()
    self._lock = threading.Lock()
    self._status: dict[str, Any] = {
      "stage": "arming",
      "title": "Arming oracle bringup",
      "detail": "Preparing the direct-Panda startup catcher.",
      "progress": 0,
      "awaiting_continue": False,
      "done": False,
      "error": False,
    }
    self._last_output = ""
    self._proc: subprocess.Popen[str] | None = None
    self._run_dir: Path | None = None

    self._title = self._child(Label("TSS3 Oracle Bringup", 74, FontWeight.BOLD, text_color=TEXT))
    self._stage_title = self._child(Label(lambda: self._snapshot()["title"], 62, FontWeight.BOLD, text_color=TEXT))
    self._detail = self._child(Label(lambda: self._snapshot()["detail"], 43, FontWeight.NORMAL,
                                     text_alignment=TextAlignment.CENTER, text_color=rl.Color(205, 205, 205, 255)))
    self._run_path = self._child(Label(lambda: str(self._run_dir) if self._run_dir is not None else "", 30,
                                       FontWeight.NORMAL, text_color=MUTED))
    self._action = self._child(Button("WORKING", self._on_action, font_size=48, button_style=ButtonStyle.PRIMARY))

    self._start_worker()

  def show_event(self):
    global _oracle_bringup_visible
    super().show_event()
    _oracle_bringup_visible = True

  def hide_event(self):
    global _oracle_bringup_visible
    _oracle_bringup_visible = False
    status = self._snapshot()
    proc = self._proc
    if proc is not None and proc.poll() is None and not status.get("done") and not status.get("error"):
      proc.terminate()
    super().hide_event()

  def _snapshot(self) -> dict[str, Any]:
    with self._lock:
      return dict(self._status)

  def _set_status(self, status: dict[str, Any]):
    with self._lock:
      self._status = dict(status)

  def _start_worker(self):
    if not tool_available():
      self._set_status({
        "stage": "error", "title": "Oracle tool unavailable",
        "detail": f"Expected {TOOL_PATH}", "progress": 0,
        "awaiting_continue": False, "done": False, "error": True,
      })
      return

    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime())
    self._run_dir = RUN_ROOT / f"{stamp}-{os.getpid()}"
    cmd = [str(TOOL_PATH), "--topology", "camry-post-repin", "oracle-ui-bringup", str(self._run_dir)]
    try:
      self._proc = subprocess.Popen(
        cmd,
        cwd=str(TOOL_PATH.parent),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
      )
    except OSError as exc:
      self._set_status({
        "stage": "error", "title": "Could not start oracle bringup",
        "detail": f"{type(exc).__name__}: {exc}", "progress": 0,
        "awaiting_continue": False, "done": False, "error": True,
      })
      return

    threading.Thread(target=self._reader, name="tss3_oracle_ui", daemon=True).start()

  def _reader(self):
    assert self._proc is not None and self._proc.stdout is not None
    for raw in self._proc.stdout:
      line = raw.strip()
      if not line:
        continue
      try:
        status = json.loads(line)
      except json.JSONDecodeError:
        with self._lock:
          self._last_output = line
        continue
      if isinstance(status, dict) and status.get("schema") == STATUS_SCHEMA:
        self._set_status(status)

    rc = self._proc.wait()
    status = self._snapshot()
    if not status.get("done") and not status.get("error"):
      with self._lock:
        detail = self._last_output or f"backend exited with status {rc}"
      self._set_status({
        "stage": "error", "title": "Oracle bringup stopped",
        "detail": detail, "progress": 0,
        "awaiting_continue": False, "done": False, "error": True,
      })

  def _send_continue(self):
    proc = self._proc
    if proc is None or proc.poll() is not None or proc.stdin is None:
      return
    try:
      proc.stdin.write("\n")
      proc.stdin.flush()
      status = self._snapshot()
      status["awaiting_continue"] = False
      status["detail"] = "Continuing..."
      self._set_status(status)
    except (BrokenPipeError, OSError):
      pass

  def _on_action(self):
    status = self._snapshot()
    if status.get("awaiting_continue"):
      self._send_continue()
    elif status.get("done") or status.get("error"):
      gui_app.pop_widget()

  def _render_steps(self, rect: rl.Rectangle, stage: str):
    current = STAGE_STEP.get(stage, 0)
    item_h = 72
    gap = 10
    y = rect.y
    font = gui_app.font(FontWeight.MEDIUM)
    for i, text in enumerate(STEPS):
      row = rl.Rectangle(rect.x, y, rect.width, item_h)
      if current > i:
        color = DONE
        marker = "✓"
      elif current == i:
        color = ACTIVE
        marker = "●"
      else:
        color = MUTED
        marker = "○"
      rl.draw_text_ex(font, marker, rl.Vector2(row.x, row.y + 10), 44, 0, color)
      rl.draw_text_ex(font, text, rl.Vector2(row.x + 70, row.y + 8), 44, 0, color if current >= i else MUTED)
      y += item_h + gap

  def _render(self, rect: rl.Rectangle):
    status = self._snapshot()
    stage = str(status.get("stage", "arming"))
    progress = max(0, min(100, int(status.get("progress", 0))))

    rl.draw_rectangle_rec(rect, BACKGROUND)
    margin_x = max(60, rect.width * 0.05)
    margin_y = max(45, rect.height * 0.06)
    card = rl.Rectangle(rect.x + margin_x, rect.y + margin_y,
                        rect.width - 2 * margin_x, rect.height - 2 * margin_y)
    rl.draw_rectangle_rounded(card, 0.04, 24, CARD)

    self._title.render(rl.Rectangle(card.x + 60, card.y + 25, card.width - 120, 90))

    body_y = card.y + 135
    body_h = card.height - 185
    left_w = card.width * 0.45
    split_x = card.x + left_w

    # Progress ladder on the left.
    steps_rect = rl.Rectangle(card.x + 80, body_y + 15, left_w - 130, body_h - 95)
    self._render_steps(steps_rect, stage)

    # Current stage and controls on the right.
    right_x = split_x + 35
    right_w = card.x + card.width - 70 - right_x
    self._stage_title.render(rl.Rectangle(right_x, body_y + 5, right_w, 90))
    self._detail.render(rl.Rectangle(right_x + 10, body_y + 105, right_w - 20, 190))

    bar = rl.Rectangle(right_x + 25, body_y + 325, right_w - 50, 22)
    rl.draw_rectangle_rounded(bar, 1.0, 10, rl.Color(63, 63, 63, 255))
    if progress:
      fill = rl.Rectangle(bar.x, bar.y, bar.width * progress / 100.0, bar.height)
      rl.draw_rectangle_rounded(fill, 1.0, 10, ERROR if status.get("error") else ACTIVE)

    if self._run_dir is not None:
      self._run_path.render(rl.Rectangle(right_x + 15, body_y + 385, right_w - 30, 70))

    awaiting = bool(status.get("awaiting_continue"))
    terminal = bool(status.get("done") or status.get("error"))
    if awaiting:
      self._action.set_text("CONTINUE")
      self._action.set_button_style(ButtonStyle.PRIMARY)
      self._action.set_enabled(True)
    elif terminal:
      self._action.set_text("CLOSE")
      self._action.set_button_style(ButtonStyle.DANGER if status.get("error") else ButtonStyle.PRIMARY)
      self._action.set_enabled(True)
    else:
      self._action.set_text("WORKING")
      self._action.set_button_style(ButtonStyle.NO_EFFECT)
      self._action.set_enabled(False)

    self._action.render(rl.Rectangle(right_x + 70, card.y + card.height - 145, right_w - 140, 100))

