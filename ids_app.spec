# ids_app.spec — DEPRECATED (Phase-1 placeholder, NOT used in delivery)
# ─────────────────────────────────────────────────────────────────────────────
# This spec was written during Phase 1 before the live monitor, honeypot,
# HTTP flood middleware, and current ML pipeline existed. It will not produce
# a working executable against the current codebase.
#
# The project is delivered as Python source + batch launchers (see DELIVERY.md
# for the rationale). To run the system, double-click LAUNCH_IDS.bat in the
# project root.
#
# This file is retained only to document that PyInstaller was evaluated and
# rejected. It is intentionally non-functional. Do not run pyinstaller against
# it — the resulting bundle would be missing the live monitor, honeypot, and
# middleware modules added in later phases, and would also fail to load
# CustomTkinter assets reliably on Windows.
# ─────────────────────────────────────────────────────────────────────────────

raise SystemExit(
    "ids_app.spec is deprecated. Use LAUNCH_IDS.bat instead. See DELIVERY.md."
)
