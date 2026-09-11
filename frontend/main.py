# frontend/main.py
# ─────────────────────────────────────────────────────────────────────────────
# Desktop application entry point.
# Run with: python frontend/main.py  (from project root)
# ─────────────────────────────────────────────────────────────────────────────
import sys
from pathlib import Path

# Ensure project root is on the path when running directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from frontend.app import IDSApp


def main():
    app = IDSApp()
    app.mainloop()


if __name__ == "__main__":
    main()
