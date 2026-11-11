"""Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Variable — line 240
# definition: __init__ — line 243
# parameter: self — line 243
# parameter: value — line 243
# attribute: callbacks — line 245
# attribute: value — line 245
# definition: get — line 247
# parameter: self — line 247
# definition: set — line 251
# parameter: self — line 251
# parameter: value — line 251
# attribute: value — line 253
# variable: callback — line 254
# definition: trace_add — line 257
# parameter: _event — line 257
# parameter: callback — line 257
# parameter: self — line 257
# definition: Widget — line 262
# definition: __init__ — line 265
# parameter: _args — line 265
# parameter: kwargs — line 265
# parameter: self — line 265
# attribute: options — line 267
# attribute: rows — line 267
# attribute: selected — line 267
# attribute: flags — line 268
# attribute: tk — line 269
# parameter: _items — line 269
# definition: pack — line 271
# parameter: _kwargs — line 271
# parameter: self — line 271
# definition: grid — line 274
# parameter: _kwargs — line 274
# parameter: self — line 274
# definition: grid_remove — line 277
# parameter: self — line 277
# definition: columnconfigure — line 280
# parameter: _args — line 280
# parameter: _kwargs — line 280
# parameter: self — line 280
# definition: add — line 283
# parameter: _args — line 283
# parameter: _kwargs — line 283
# parameter: self — line 283
# definition: theme_use — line 286
# parameter: _args — line 286
# parameter: self — line 286
# definition: configure — line 289
# parameter: _args — line 289
# parameter: kwargs — line 289
# parameter: self — line 289
# definition: heading — line 293
# parameter: _args — line 293
# parameter: _kwargs — line 293
# parameter: self — line 293
# definition: column — line 296
# parameter: _args — line 296
# parameter: _kwargs — line 296
# parameter: self — line 296
# definition: bind — line 299
# parameter: _args — line 299
# parameter: self — line 299
# definition: yview — line 302
# parameter: _args — line 302
# parameter: self — line 302
# definition: set — line 305
# parameter: _args — line 305
# parameter: self — line 305
# definition: state — line 308
# parameter: flags — line 308
# parameter: self — line 308
# variable: flag — line 310
# definition: invoke — line 316
# parameter: self — line 316
# definition: insert — line 322
# parameter: _parent — line 322
# parameter: _position — line 322
# parameter: iid — line 322
# parameter: self — line 322
# parameter: values — line 322
# definition: delete — line 326
# parameter: items — line 326
# parameter: self — line 326
# variable: item — line 328
# attribute: selected — line 330
# variable: item — line 330
# definition: get_children — line 332
# parameter: self — line 332
# definition: selection — line 336
# parameter: self — line 336
# definition: selection_set — line 340
# parameter: identity — line 340
# parameter: self — line 340
# attribute: selected — line 343
# definition: Text — line 346
# definition: delete — line 349
# parameter: _args — line 349
# parameter: self — line 349
# attribute: text — line 351
# definition: insert — line 353
# parameter: _position — line 353
# parameter: self — line 353
# parameter: text — line 353
# attribute: text — line 355
# definition: Root — line 358
# definition: __init__ — line 361
# parameter: self — line 361
# attribute: callbacks — line 363
# attribute: destroyed — line 363
# attribute: on_loop — line 364
# definition: title — line 366
# parameter: _args — line 366
# parameter: self — line 366
# definition: geometry — line 369
# parameter: _args — line 369
# parameter: self — line 369
# definition: minsize — line 372
# parameter: _args — line 372
# parameter: self — line 372
# definition: protocol — line 375
# parameter: _event — line 375
# parameter: callback — line 375
# parameter: self — line 375
# attribute: close_callback — line 377
# definition: after — line 379
# parameter: _delay — line 379
# parameter: callback — line 379
# parameter: self — line 379
# definition: destroy — line 383
# parameter: self — line 383
# attribute: destroyed — line 385
# definition: mainloop — line 387
# parameter: self — line 387
# variable: _ — line 391
# definition: presentation — line 399
# parameter: monkeypatch — line 399
# parameter: _parent — line 404
# variable: name — line 406
# variable: messages — line 420
# parameter: _kwargs — line 422
# parameter: args — line 422
# parameter: _kwargs — line 425
# parameter: args — line 425
# definition: app — line 431
# parameter: presentation — line 431
# parameter: tmp_path — line 431
# variable: state — line 433
# variable: root — line 434
# variable: window — line 435
# definition: settle — line 449
# parameter: window — line 449
# variable: deadline — line 451
# definition: test_real_controller_run_filter_detail_history_export_and_help — line 458
# parameter: app — line 459
# parameter: monkeypatch — line 459
# parameter: presentation — line 459
# parameter: tmp_path — line 459
# parameter: _kwargs — line 484
# variable: original — line 486
# variable: exported — line 488
# variable: path — line 489
# parameter: _kwargs — line 494
# definition: test_explicit_retention_confirmation_removes_only_selected_local_copy — line 500
# parameter: app — line 501
# parameter: monkeypatch — line 501
# parameter: tmp_path — line 501
# variable: exported — line 511
# variable: original — line 512
# parameter: _args — line 513
# parameter: _kwargs — line 513
# parameter: _args — line 516
# parameter: _kwargs — line 516
# variable: path — line 519
# attribute: busy — line 520
# attribute: busy — line 523
# definition: test_exact_episode_selection_reasoned_save_and_repeat_are_real_core — line 526
# parameter: app — line 526
# variable: original — line 537
# variable: episode — line 548
# variable: files — line 556
# variable: rows — line 558
# variable: row — line 560
# attribute: busy — line 569
# attribute: busy — line 572
# definition: test_input_selection_cancel_busy_failure_and_literal_row_cap — line 575
# parameter: app — line 576
# parameter: monkeypatch — line 576
# parameter: tmp_path — line 576
# variable: name — line 579
# parameter: _kwargs — line 583
# parameter: _kwargs — line 588
# parameter: _kwargs — line 591
# variable: kind — line 593
# variable: value — line 597
# parameter: _kwargs — line 598
# attribute: busy — line 601
# attribute: busy — line 607
# attribute: current — line 614
# variable: index — line 623
# definition: test_close_retains_lock_until_actual_core_transaction_finishes — line 637
# parameter: app — line 638
# parameter: monkeypatch — line 638
# parameter: tmp_path — line 638
# variable: ready — line 641
# variable: release — line 641
# variable: actual — line 642
# definition: pause — line 644
# parameter: args — line 644
# variable: reopened — line 662
# definition: test_main_native_close_and_rejected_acceptance_paths — line 669
# parameter: monkeypatch — line 670
# parameter: presentation — line 670
# parameter: tmp_path — line 670
# variable: actual — line 673
# definition: create — line 675
# parameter: root — line 675
# parameter: state — line 675
# variable: window — line 677
# attribute: on_loop — line 678
# variable: profile — line 682
# variable: reopened — line 684
# variable: unknown — line 708
# END CODE MAP

import json
import threading
import time
from types import SimpleNamespace

import pytest

from runtime_lab import desktop as module
from runtime_lab import desktop_project as project
from runtime_lab.desktop_io import Rejected
from runtime_lab.desktop_state import Workspace


class Variable:
    """Inert presentation variable; invokes the same registered GUI trace callbacks."""

    def __init__(self, value=""):
        """Keep a scalar control value and registered change callbacks."""
        self.value, self.callbacks = value, []

    def get(self):
        """Return the current presentation control value."""
        return self.value

    def set(self, value):
        """Change a control and exercise actual application rendering callbacks."""
        self.value = value
        for callback in self.callbacks:
            callback()

    def trace_add(self, _event, callback):
        """Retain the GUI's value-change handler."""
        self.callbacks.append(callback)


class Widget:
    """Minimal inert ttk presentation adapter; no core, storage or analysis output is mocked."""

    def __init__(self, *_args, **kwargs):
        """Retain properties, rows and command closures."""
        self.options, self.rows, self.selected = kwargs, {}, ()
        self.flags = set()
        self.tk = SimpleNamespace(call=lambda *_items: None)

    def pack(self, **_kwargs):
        """Accept presentation layout."""

    def grid(self, **_kwargs):
        """Accept presentation grid coordinates."""

    def grid_remove(self):
        """Accept operation-specific hidden controls."""

    def columnconfigure(self, *_args, **_kwargs):
        """Accept resize weights."""

    def add(self, *_args, **_kwargs):
        """Accept notebook/paned-window children."""

    def theme_use(self, *_args):
        """Accept native style selection."""

    def configure(self, *_args, **kwargs):
        """Retain updated widget options."""
        self.options.update(kwargs)

    def heading(self, *_args, **_kwargs):
        """Accept a literal table heading."""

    def column(self, *_args, **_kwargs):
        """Accept table sizing."""

    def bind(self, *_args):
        """Accept event registration; tests invoke actual handlers explicitly."""

    def yview(self, *_args):
        """Accept scroll requests."""

    def set(self, *_args):
        """Accept scrollbar position updates."""

    def state(self, flags):
        """Preserve disabled controls so a simulated click cannot bypass a busy guard."""
        for flag in flags:
            if flag.startswith("!"):
                self.flags.discard(flag[1:])
            else:
                self.flags.add(flag)

    def invoke(self):
        """Invoke the actual registered command unless the control is disabled."""
        if "disabled" not in self.flags:
            return self.options["command"]()
        return None

    def insert(self, _parent, _position, *, iid, values):
        """Retain exact rows inserted by real project rendering."""
        self.rows[iid] = values

    def delete(self, *items):
        """Remove rows and their selections like a real treeview."""
        for item in items:
            self.rows.pop(item, None)
        self.selected = tuple(item for item in self.selected if item in self.rows)

    def get_children(self):
        """Return displayed row identities."""
        return tuple(self.rows)

    def selection(self):
        """Return the current selected row identity."""
        return self.selected

    def selection_set(self, identity):
        """Select one existing row like a real single-selection control."""
        assert identity in self.rows
        self.selected = (identity,)


class Text(Widget):
    """Retain literal detail output without interpreting markup or executing event fields."""

    def delete(self, *_args):
        """Clear existing literal detail text."""
        self.text = ""

    def insert(self, _position, text):
        """Retain the exact rendered detail text."""
        self.text = text


class Root:
    """Deterministic presentation event queue; actual Tk mainloops are independently exercised by frozen acceptance."""

    def __init__(self):
        """Create a fresh owned presentation root."""
        self.callbacks, self.destroyed = [], False
        self.on_loop = None

    def title(self, *_args):
        """Accept window title."""

    def geometry(self, *_args):
        """Accept initial geometry."""

    def minsize(self, *_args):
        """Accept minimum geometry."""

    def protocol(self, _event, callback):
        """Keep the application's native close callback."""
        self.close_callback = callback

    def after(self, _delay, callback):
        """Queue the actual lifecycle callback without a platform display server."""
        self.callbacks.append(callback)

    def destroy(self):
        """Mark only this owned root as closed."""
        self.destroyed = True

    def mainloop(self):
        """Run the requested test lifecycle using real application callbacks."""
        if self.on_loop:
            self.on_loop()
        for _ in range(200):
            if self.destroyed:
                return
            self.callbacks.pop(0)()
        raise AssertionError("presentation lifecycle did not close")


@pytest.fixture
def presentation(monkeypatch):
    """Replace only OS presentation surfaces; real worker, core, SQLite and export code remain active."""
    monkeypatch.setattr(module.tk, "StringVar", Variable)
    monkeypatch.setattr(module.tk, "BooleanVar", Variable)
    monkeypatch.setattr(module.tk, "Tk", Root)
    monkeypatch.setattr(module.tk, "Toplevel", lambda _parent: Root())
    monkeypatch.setattr(module.tk, "Text", Text)
    for name in (
        "Frame",
        "Label",
        "Notebook",
        "Combobox",
        "Entry",
        "Button",
        "Checkbutton",
        "Panedwindow",
        "Treeview",
        "Scrollbar",
        "Style",
    ):
        monkeypatch.setattr(module.ttk, name, Widget)
    messages = []
    monkeypatch.setattr(
        module.messagebox, "showinfo", lambda *args, **_kwargs: messages.append(args)
    )
    monkeypatch.setattr(
        module.messagebox, "showerror", lambda *args, **_kwargs: messages.append(args)
    )
    return messages


@pytest.fixture
def app(tmp_path, presentation):
    """Build the actual workbench controller against an isolated real durable workspace."""
    state = Workspace(tmp_path / "profile", project.PRODUCT, project.ROOT)
    root = Root()
    window = module.Workbench(root, state)
    # Presentation tests exercise the real offline domain engine and SQLite;
    # actual widgets/mainloop are separately proved by the final frozen consumer.
    window.prepared.set(project.SCENARIOS[0])
    window.load_prepared()
    try:
        yield window
    finally:
        if window.worker_thread:
            window.worker_thread.join(10)
            assert not window.worker_thread.is_alive()
        state.close()


def settle(window):
    """Observe completion of one actual owned analysis; no retries or invented report values."""
    deadline = time.monotonic() + 10
    while window.busy and time.monotonic() < deadline:
        window.poll()
        time.sleep(0.005)
    assert not window.busy


def test_real_controller_run_filter_detail_history_export_and_help(
    app, tmp_path, monkeypatch, presentation
):
    """Real core results drive controls, literal filters, exact private exports and history reopening."""
    app.export()
    assert "completed" in app.status.get()
    app.run_button.invoke()
    assert not app.busy and app.state.history() == []
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    assert app.selected_run == 1 and len(app.state.history()) == 1
    assert len(app.table.get_children()) > 0
    app.table.selection_set("0")
    app.inspect()
    assert "{" in app.details.text
    app.review_selected()
    assert "Only an episode" in app.status.get()
    app.search.set("not-a-supported-record-never-present")
    assert app.table.get_children() == ()
    app.inspect()
    app.search.set("")
    app.history_table.selection_set("1")
    app.open_button.invoke()
    assert "without re-running" in app.status.get()
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path)
    )
    original = app.state.files(1)
    app.export_button.invoke()
    exported = next(tmp_path.glob(project.PRODUCT + "-run-*"))
    assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
    app.help()
    assert "plaintext" in presentation[-1][1]
    app.licenses()
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path / "missing")
    )
    app.export()
    assert "unavailable" in app.status.get()


def test_explicit_retention_confirmation_removes_only_selected_local_copy(
    app, tmp_path, monkeypatch
):
    """Cancellation preserves data; confirmation deletes one exact DB bundle without touching a prior export."""
    app.remove_history()
    assert "Select" in app.status.get()
    app.review_selected()
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    app.history_table.selection_set("1")
    exported = app.state.export(1, tmp_path, project.PRODUCT)
    original = app.state.files(1)
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *_args, **_kwargs: False)
    app.remove_button.invoke()
    assert app.state.files(1) == original
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *_args, **_kwargs: True)
    app.remove_button.invoke()
    assert app.state.history() == [] and app.selected_run == 0
    assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
    app.busy = True
    app.remove_history()
    assert "Wait" in app.status.get()
    app.busy = False


def test_exact_episode_selection_reasoned_save_and_repeat_are_real_core(app):
    """A row fills ordinary controls but records nothing until an explicit acknowledged real-core operation."""
    app.review_selected()
    assert "Select" in app.status.get()
    app.group_selected()
    assert "exact saved" in app.status.get()
    app.prepared.set(project.SCENARIOS[2])
    app.load_prepared()
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    original = app.state.files(1)["review.json"]
    app.group_button.invoke()
    assert app.mode.get() == project.MODES[1] and app.values["saved_run"].get() == "1"
    assert not app.authorized.get()
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    assert app.selected_run == 2
    app.table.selection_set("0")
    app.review_button.invoke()
    assert app.mode.get() == project.MODES[2] and not app.authorized.get()
    episode = app.values["episode_id"].get()
    assert len(episode) == 64 and app.values["saved_run"].get() == "2"
    assert len(app.state.history()) == 2
    app.values["reason"].set("Compare the fictional authorized maintenance record")
    app.values["disposition"].set("expected_activity")
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    files = app.state.files(3)
    assert json.loads(files["review.json"]) == json.loads(original)
    rows = json.loads(files["episodes.json"])["episodes"]
    assert (
        next(row for row in rows if row["id"] == episode)["disposition"]
        == "expected_activity"
    )
    app.table.selection_set("0")
    app.review_button.invoke()
    assert (
        app.values["reason"].get()
        == "Compare the fictional authorized maintenance record"
    )
    app.busy = True
    app.review_selected()
    app.group_selected()
    app.busy = False


def test_input_selection_cancel_busy_failure_and_literal_row_cap(
    app, tmp_path, monkeypatch
):
    """Operator mistakes do not silently run a prepared fixture, overwrite results or defeat close semantics."""
    name = "alerts"
    monkeypatch.setattr(
        module.filedialog,
        "askopenfilename",
        lambda **_kwargs: str(tmp_path / "authorized.json"),
    )
    monkeypatch.setattr(
        module.filedialog,
        "askopenfilenames",
        lambda **_kwargs: ("one.json", "two.json"),
    )
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path)
    )
    for kind in ("file", "files", "directory"):
        app.authorized.set(True)
        app.choose(name, kind)
        assert app.authorized.get() is False
    value = app.values[name].get()
    monkeypatch.setattr(module.filedialog, "askopenfilename", lambda **_kwargs: "")
    app.choose(name, "file")
    assert app.values[name].get() == value
    app.busy = True
    app.choose(name, "file")
    app.load_prepared()
    app.open_history()
    app.run()
    assert app.state.history() == []
    app.busy = False
    app.load_prepared()
    app.mode.set("unsupported-operation")
    app.authorized.set(True)
    app.run()
    settle(app)
    assert "rejected" in app.status.get().lower() and app.state.history() == []
    app.current = {
        "bounded": [
            {
                "kind": "alert",
                "time": str(index),
                "rule": "synthetic",
                "source": "k8s_audit",
                "priority": "Warning",
            }
            for index in range(5001)
        ]
    }
    app.view.set("bounded")
    app.render()
    assert len(app.table.get_children()) == 5000
    app.search.set('"5000"')
    assert len(app.table.get_children()) == 1
    app.exit()
    app.run()
    app.poll()
    assert app.root.destroyed and app.state.lock == -1


def test_close_retains_lock_until_actual_core_transaction_finishes(
    app, tmp_path, monkeypatch
):
    """An in-flight real analysis is drained rather than abandoned, force-killed or exposed to a second owner."""
    ready, release = threading.Event(), threading.Event()
    actual = project.analyze

    def pause(*args):
        """Control only scheduling; completion still invokes the actual project core and durable output."""
        ready.set()
        assert release.wait(5)
        return actual(*args)

    monkeypatch.setattr(project, "analyze", pause)
    app.authorized.set(True)
    app.run_button.invoke()
    assert ready.wait(3)
    app.exit()
    app.poll()
    assert not app.root.destroyed and app.busy
    with pytest.raises((Rejected, OSError)):
        Workspace(app.state.path, project.PRODUCT, project.ROOT)
    release.set()
    settle(app)
    assert app.root.destroyed and app.state.lock == -1
    reopened = Workspace(app.state.path, project.PRODUCT, project.ROOT)
    try:
        assert len(reopened.history()) == 1
    finally:
        reopened.close()


def test_main_native_close_and_rejected_acceptance_paths(
    tmp_path, presentation, monkeypatch
):
    """Normal startup never auto-analyzes; test flags cannot enter existing real-profile state or claim partial success."""
    actual = module.Workbench

    def create(root, state):
        """Use actual controls/controller; request the normal close callback at the start of the event loop."""
        window = actual(root, state)
        root.on_loop = window.exit
        return window

    monkeypatch.setattr(module, "Workbench", create)
    profile = tmp_path / "normal"
    assert module.main(["--profile", str(profile)]) == 0
    reopened = Workspace(profile, project.PRODUCT, project.ROOT)
    assert reopened.history() == []
    reopened.close()
    with pytest.raises(SystemExit):
        module.main(["--acceptance-output", str(tmp_path / "output")])
    with pytest.raises(SystemExit):
        module.main(["--acceptance-reopen"])
    assert (
        module.main(
            ["--profile", str(profile), "--acceptance-output", str(tmp_path / "output")]
        )
        == 2
    )
    assert (
        module.main(
            [
                "--profile",
                str(tmp_path / "synthetic"),
                "--acceptance-output",
                str(tmp_path / "new-output"),
            ]
        )
        == 2
    )
    unknown = tmp_path / "unknown"
    unknown.mkdir()
    (unknown / "keep").write_bytes(b"unchanged")
    assert module.main(["--profile", str(unknown)]) == 2
    assert (unknown / "keep").read_bytes() == b"unchanged"
    assert presentation and "No saved evidence was reset" in presentation[-1][1]
