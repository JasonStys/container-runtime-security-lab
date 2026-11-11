"""Actual final portable widgets/core/native-window acceptance with independent oracles. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: capture — line 123
# parameter: target — line 123
# parameter: window — line 123
# variable: load — line 129
# variable: gdi — line 130
# variable: user — line 130
# variable: pointer — line 131
# variable: arguments — line 132
# variable: library — line 132
# variable: name — line 132
# variable: result — line 132
# variable: function — line 158
# attribute: argtypes — line 159
# attribute: restype — line 159
# variable: handle — line 162
# variable: rectangle — line 163
# variable: height — line 166
# variable: width — line 166
# variable: source — line 169
# variable: destination — line 170
# variable: bitmap — line 171
# variable: previous — line 172
# variable: pixels — line 177
# variable: header — line 178
# variable: raw — line 196
# variable: scanlines — line 197
# variable: row — line 198
# variable: column — line 200
# variable: offset — line 201
# definition: chunk — line 204
# parameter: data — line 204
# parameter: name — line 204
# definition: oracle — line 226
# parameter: files — line 226
# parameter: index — line 226
# variable: value — line 228
# variable: expected — line 229
# variable: raw — line 243
# variable: grouped — line 251
# variable: r — line 258
# variable: r — line 260
# variable: r — line 263
# variable: r — line 268
# definition: exercise — line 273
# parameter: output — line 273
# parameter: reopen — line 273
# parameter: window — line 273
# variable: expected — line 278
# variable: started — line 278
# variable: receipt — line 279
# variable: deadline — line 296
# definition: progress — line 298
# parameter: stage — line 298
# definition: finish — line 305
# parameter: failed — line 305
# attribute: acceptance_result — line 307
# variable: name — line 315
# variable: raw — line 315
# variable: row — line 317
# definition: checked — line 322
# parameter: callback — line 322
# variable: trace — line 330
# variable: trace — line 338
# definition: callback_failed — line 341
# parameter: _traceback — line 342
# parameter: _value — line 342
# parameter: kind — line 342
# definition: wait — line 348
# parameter: callback — line 348
# definition: layout — line 358
# variable: widgets — line 363
# variable: name — line 364
# variable: widget — line 366
# definition: rejected — line 388
# definition: licenses — line 397
# variable: dialogs — line 400
# variable: child — line 402
# variable: dialog — line 406
# variable: pending — line 407
# variable: texts — line 408
# variable: widget — line 410
# variable: text — line 416
# variable: value — line 417
# definition: completed — line 421
# parameter: index — line 421
# variable: files — line 427
# variable: parent — line 454
# variable: target — line 460
# variable: path — line 461
# variable: selected — line 464
# definition: start — line 476
# parameter: index — line 476
# variable: selected — line 500
# definition: begin — line 514
# variable: identity — line 518
# attribute: report_callback_exception — line 534
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import tkinter as tk
import zlib
from pathlib import Path
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from runtime_lab import desktop_project as project
from runtime_lab.desktop_io import json_value

if TYPE_CHECKING:
    from runtime_lab.desktop import Workbench


def capture(window: Workbench, target: Path) -> None:
    """Capture only this owned synthetic Tk window via PrintWindow, never the user's whole desktop."""
    if sys.platform != "win32":
        raise OSError("native screenshot acceptance targets Windows")
    from ctypes import wintypes

    load = ctypes.WinDLL
    user, gdi = load("user32", use_last_error=True), load("gdi32", use_last_error=True)
    pointer = ctypes.c_void_p
    for library, name, arguments, result in [
        (user, "GetAncestor", [pointer, ctypes.c_uint], pointer),
        (user, "GetWindowDC", [pointer], pointer),
        (gdi, "CreateCompatibleDC", [pointer], pointer),
        (gdi, "CreateCompatibleBitmap", [pointer, ctypes.c_int, ctypes.c_int], pointer),
        (gdi, "SelectObject", [pointer, pointer], pointer),
        (gdi, "DeleteObject", [pointer], ctypes.c_int),
        (gdi, "DeleteDC", [pointer], ctypes.c_int),
        (user, "ReleaseDC", [pointer, pointer], ctypes.c_int),
        (user, "PrintWindow", [pointer, pointer, ctypes.c_uint], ctypes.c_int),
        (user, "GetWindowRect", [pointer, ctypes.POINTER(wintypes.RECT)], ctypes.c_int),
        (
            gdi,
            "GetDIBits",
            [
                pointer,
                pointer,
                ctypes.c_uint,
                ctypes.c_uint,
                pointer,
                pointer,
                ctypes.c_uint,
            ],
            ctypes.c_int,
        ),
    ]:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    # Flush this owned native window's pending control messages before reading its pixels.
    window.root.update()
    handle = user.GetAncestor(window.root.winfo_id(), 2)
    rectangle = wintypes.RECT()
    if not user.GetWindowRect(handle, ctypes.byref(rectangle)):
        raise OSError("owned window bounds unavailable")
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise OSError("owned screenshot outside bounded dimensions")
    source = user.GetWindowDC(handle)
    destination = gdi.CreateCompatibleDC(source)
    bitmap = gdi.CreateCompatibleBitmap(source, width, height)
    previous = gdi.SelectObject(destination, bitmap)
    try:
        if not user.PrintWindow(handle, destination, 2):
            raise OSError("owned window rendering unavailable")
        gdi.SelectObject(destination, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(
            struct.pack(
                "<IiiHHIIiiII",
                40,
                width,
                -height,
                1,
                32,
                0,
                width * height * 4,
                0,
                0,
                0,
                0,
            )
        )
        if gdi.GetDIBits(source, bitmap, 0, height, pixels, header, 0) != height:
            raise OSError("owned screenshot pixels incomplete")
        raw = pixels.raw
        scanlines = bytearray()
        for row in range(height):
            scanlines.append(0)
            for column in range(width):
                offset = (row * width + column) * 4
                scanlines.extend((raw[offset + 2], raw[offset + 1], raw[offset]))

        def chunk(name: bytes, data: bytes) -> bytes:
            """Encode a bounded standard PNG chunk with its actual CRC."""
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data))
            )

        target.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines)))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi.SelectObject(destination, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(destination)
        user.ReleaseDC(handle, source)


def oracle(index: int, files: dict[str, bytes]) -> None:
    """Assert fixed independent privacy/health/grouping counts and original denominator preservation."""
    value = json_value(files["review.json"])
    expected = (
        (3, 0, 0),
        (3, 0, 2),
        (5, 1, 0),
        (5, 1, 2),
        (0, 0, 0),
        (5, 1, 0),
        (5, 1, 2),
        (5, 1, 0),
        (5, 1, 0),
    )
    assert (value["unique"], value["duplicates"], len(value["gaps"])) == expected[index]
    assert not any(
        raw in b"".join(files.values())
        for raw in (
            b"synthetic-workload",
            b"synthetic-container-1",
            b"fake-secret",
            b"/tmp/crsl-sensitive-marker",
        )
    )
    if index >= 5:
        grouped = json_value(files["episodes.json"])
        assert grouped["original_review"] == value
        assert len(grouped["episodes"]) == (5 if index in (6, 7) else 3)
        assert len(grouped["unreviewed_episode_ids"]) == (
            2 if index == 8 else len(grouped["episodes"])
        )
        if index == 5:
            assert sorted(len(r["event_ids"]) for r in grouped["episodes"]) == [1, 1, 3]
        if index == 6:
            assert all(len(r["event_ids"]) == 1 for r in grouped["episodes"])
        if index == 8:
            assert (
                sum(r["disposition"] == "needs_context" for r in grouped["episodes"])
                == 1
            )
            assert all(
                len(r["reason"]) >= 5
                for r in grouped["episodes"]
                if r["disposition"] != "unreviewed"
            )


def exercise(window: Workbench, output: Path, reopen: bool) -> None:
    """Drive the same real offline widgets/core worker and retained-owner close; supply only OS file-picker selection."""
    from unittest.mock import patch

    output.mkdir(mode=0o700)
    started, expected = time.monotonic(), 9
    receipt: dict[str, Any] = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": project.VERSION,
        "source": window.identity["source"],
        "source_dirty": window.identity["source_dirty"],
        "python_version": sys.version.split()[0],
        "python_dll_sha256": window.identity.get("python_dll_sha256"),
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "synthetic": True,
        "reopen": reopen,
        "passed": False,
        "steps": [],
        "tcl_version": str(window.root.tk.call("info", "patchlevel")),
        "tk_version": str(window.root.tk.call("package", "require", "Tk")),
    }
    deadline = started + 65

    def progress(stage: str) -> None:
        """Keep value-free milestone evidence if a native service or UI step fails."""
        receipt["last_stage"] = stage
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )

    def finish(failed: bool = False) -> None:
        """Request normal close and preserve exact bundle identities; failure is never replaced by success on cleanup."""
        window.acceptance_result = not failed
        receipt["passed"] = not failed
        if failed:
            receipt["safe_application_status"] = window.status.get()[:240]
        receipt["journey_elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        receipt["bundles"] = {
            str(row["id"]): {
                name: hashlib.sha256(raw).hexdigest()
                for name, raw in window.state.files(row["id"]).items()
            }
            for row in window.state.history()
        }
        progress("failed-retained" if failed else "normal-close-requested")
        window.exit()

    def checked(callback: Any) -> None:
        """A failed assertion becomes a nonzero normal app exit, without private exception/body output."""
        try:
            callback()
        except Exception as error:
            receipt["failure_stage"] = callback.__name__
            receipt["failure_type"] = type(error).__name__[:60]
            receipt["failure_step"] = receipt.get("last_stage")
            trace = error.__traceback__
            while trace is not None:
                if (
                    Path(trace.tb_frame.f_code.co_filename).name
                    == "native_acceptance.py"
                ):
                    receipt["failure_function"] = trace.tb_frame.f_code.co_name[:60]
                    receipt["failure_line"] = trace.tb_lineno
                trace = trace.tb_next
            finish(True)

    def callback_failed(
        kind: type[BaseException], _value: BaseException, _traceback: Any
    ) -> None:
        """Do not lose Tk callback errors in a windowed executable without stderr."""
        receipt["failure_type"] = kind.__name__[:60]
        finish(True)

    def wait(callback: Any) -> None:
        """Wait for the actual retained worker with one fixed deadline; no audit repetition or forced child abandonment."""
        if time.monotonic() > deadline:
            receipt["failure_stage"] = "owned-workflow-deadline"
            finish(True)
        elif window.busy:
            window.root.after(60, lambda: wait(callback))
        else:
            checked(callback)

    def layout() -> None:
        """Require real active controls and Exit to fit the minimum supported native window."""
        window.root.geometry("980x700")
        window.tabs.tk.call(str(window.tabs), "select", str(window.inputs_page))
        window.root.update()
        widgets: list[ttk.Widget] = [window.run_button, *window.footer_buttons.values()]
        for name in project.ACTIVE_FIELDS[window.mode.get()]:
            widgets.extend(window.field_widgets[name])
        for widget in widgets:
            assert widget.winfo_ismapped()
            assert (
                widget.winfo_rootx() >= window.root.winfo_rootx()
                and widget.winfo_rooty() >= window.root.winfo_rooty()
            )
            assert (
                widget.winfo_rootx() + widget.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                widget.winfo_rooty() + widget.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        receipt["minimum_layout"] = {
            "width": 980,
            "height": 700,
            "activeInputsRunAndLifecycleVisible": True,
        }
        window.root.geometry("1260x860")
        window.root.update()

    def rejected() -> None:
        """A duplicate-key selected input must preserve every earlier real result and produce a visible rejection."""
        assert (
            len(window.state.history()) == expected
            and "rejected" in window.status.get().lower()
        )
        receipt["steps"].append("actual-invalid-input-retains-all-bundles")
        finish()

    def licenses() -> None:
        """Inspect the actual bundled text notice window, not a source-only declaration that licenses exist."""
        window.licenses()
        dialogs = [
            child
            for child in window.root.winfo_children()
            if isinstance(child, tk.Toplevel)
        ]
        assert len(dialogs) == 1
        dialog = dialogs[0]
        pending: list[tk.Misc] = [dialog]
        texts: list[tk.Text] = []
        while pending:
            widget = pending.pop()
            if isinstance(widget, tk.Text):
                texts.append(widget)
            pending.extend(widget.winfo_children())
            assert len(pending) < 1000
        assert len(texts) == 1
        text = texts[0].get("1.0", "end")
        assert all(value in text for value in ("Python", "Tcl", "Tk"))
        dialog.destroy()
        receipt["steps"].append("actual-bundled-runtime-license-window")

    def completed(index: int) -> None:
        """Read actual original outputs and inspect real rows; no service response or analysis result is mocked."""
        assert (
            len(window.state.history()) == index + 1
            and window.selected_run == index + 1
        )
        files = window.state.files(index + 1)
        oracle(index, files)
        if index in (2, 8):
            window.view.set(
                "Original normalized alerts"
                if index == 2
                else "Coverage-aware episodes"
            )
            window.render()
            window.table.selection_set("0")
            window.inspect()
            assert json.loads(window.details.get("1.0", "end"))
            window.root.update()
            capture(
                window,
                output
                / (
                    "selected-evidence.png" if index < 8 else "owner-unknown-review.png"
                ),
            )
        receipt["steps"].append("actual-workflow-" + str(index + 1))
        if index + 1 < expected:
            start(index + 1)
        else:
            progress("runtime-license-window")
            licenses()
            progress("exact-export")
            parent = output / "exact-export"
            parent.mkdir()
            with patch(
                "runtime_lab.desktop.filedialog.askdirectory", return_value=str(parent)
            ):
                window.export_button.invoke()
            target = next(parent.iterdir())
            assert {path.name: path.read_bytes() for path in target.iterdir()} == files
            receipt["steps"].append("actual-exact-export")
            progress("invalid-report-retention")
            selected = output / "duplicate-key.json"
            selected.write_text('{"schema":1,"schema":2}', encoding="utf-8")
            window.mode.set(project.MODES[0])
            with patch(
                "runtime_lab.desktop.filedialog.askopenfilename",
                return_value=str(selected),
            ):
                window.choose("alerts", "file")
            window.authorized.set(True)
            window.run_button.invoke()
            wait(rejected)

    def start(index: int) -> None:
        """Prepared scenarios set ordinary controls; a real copied external report is selected through the same chooser."""
        progress("workflow-" + str(index + 1))
        if index == 8:
            window.show(6)
            window.view.set("Coverage-aware episodes")
            window.render()
            window.table.selection_set("0")
            assert window.review_button is not None
            window.review_button.invoke()
            assert window.mode.get() == project.MODES[2]
            window.values["disposition"].set("needs_context")
            window.values["reason"].set(
                "Correlate the fictional approved change and retained original evidence"
            )
        else:
            window.prepared.set(project.SCENARIOS[index])
            window.load_prepared()
            if index >= 5:
                window.show(4 if index == 6 else 3)
                window.group_button.invoke()
                window.values["gap_seconds"].set("5" if index == 7 else "30")
        assert not window.authorized.get()
        if index == 2:
            selected = output / "authorized-alerts.jsonl"
            selected.write_bytes(
                (project.ROOT / "examples/desktop/episode-alerts.jsonl").read_bytes()
            )
            with patch(
                "runtime_lab.desktop.filedialog.askopenfilename",
                return_value=str(selected),
            ):
                window.choose("alerts", "file")
        layout()
        window.authorized.set(True)
        window.run_button.invoke()
        wait(lambda: completed(index))

    def begin() -> None:
        """A separate real process reopens all exact bundles without rerunning services or recomputing a prior report."""
        if reopen:
            assert len(window.state.history()) == expected
            for identity in range(1, expected + 1):
                window.history_table.selection_set(str(identity))
                window.open_button.invoke()
                assert window.selected_run == identity
                oracle(identity - 1, window.state.files(identity))
            receipt["steps"].append("actual-process-reopen-all-exact-bundles")
            finish()
        else:
            assert not window.state.history()
            window.run_button.invoke()
            assert (
                not window.state.history()
                and "permission" in window.status.get().lower()
            )
            start(0)

    window.root.report_callback_exception = callback_failed
    checked(begin)
