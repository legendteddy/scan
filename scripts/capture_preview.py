#!/usr/bin/env python3
"""Optional visual QA and preview PNG refresh; requires Playwright + Chromium.

Install separately: python -m pip install playwright && python -m playwright install chromium
Not needed to use Scan, validate a report, or run CI.
"""
from pathlib import Path
import tempfile

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "examples" / "demo-report.html"
SOCIAL = ROOT / "assets" / "social-preview.svg"


def main():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 780},
                                      device_scale_factor=1, java_script_enabled=False)
        page = context.new_page()
        external = []
        page.on("request", lambda req: external.append(req.url) if req.url.startswith(("http:", "https:")) else None)
        page.goto(REPORT.as_uri(), wait_until="load")
        assert page.locator("#project-anatomy-state").count() == 1
        assert page.locator("h1").count() == 1
        assert page.locator("table.table-checks tbody tr").count() == 14
        assert not external, f"Unexpected remote requests: {external}"
        page.screenshot(path=str(ROOT / "assets" / "demo-preview.png"),
                        clip={"x": 0, "y": 0, "width": 1280, "height": 780})
        context.close()

        mobile = browser.new_context(viewport={"width": 390, "height": 844},
                                     device_scale_factor=1, java_script_enabled=False)
        small = mobile.new_page()
        small.goto(REPORT.as_uri(), wait_until="load")
        # Long evidence tables scroll within their own region, not the whole page.
        widths = small.evaluate("""() => ({
            viewport: document.documentElement.clientWidth,
            page: document.documentElement.scrollWidth,
            tables: document.querySelectorAll('.table-scroll').length
        })""")
        assert widths["page"] <= widths["viewport"] + 2, f"Horizontal page overflow: {widths}"
        assert widths["tables"] >= 3, "Missing scrollable appendix tables"
        with tempfile.TemporaryDirectory() as tmp:
            small.screenshot(path=str(Path(tmp) / "mobile.png"), full_page=True)
            small.emulate_media(media="print")
            small.screenshot(path=str(Path(tmp) / "print.png"), full_page=False)
        mobile.close()

        social_context = browser.new_context(viewport={"width": 1280, "height": 640},
                                             device_scale_factor=1)
        social = social_context.new_page()
        social.goto(SOCIAL.as_uri(), wait_until="load")
        social.screenshot(path=str(ROOT / "assets" / "social-preview.png"),
                          clip={"x": 0, "y": 0, "width": 1280, "height": 640})
        social_context.close()
        browser.close()
        print("PASS: desktop, mobile and print render checks; no external requests")
        print("Wrote assets/demo-preview.png and assets/social-preview.png")


if __name__ == "__main__":
    main()
