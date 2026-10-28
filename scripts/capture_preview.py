"""Optional current-report visual acceptance; requires Playwright + Chromium.

Every report context disables JavaScript. Browser evaluate calls inspect layout;
they are not shipped in reports. No dependency is added to the Scan package.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from playwright.sync_api import sync_playwright
from scan_core.validate import validate_report

WIDTHS = (390, 768, 1024, 1280, 1536)
ANCHORS = ('verdict', 'findings', 'changes', 'coverage', 'architecture', 'actions', 'audit')


def structural(page, state):
    assert page.locator('h1').count() == 1
    assert page.locator('main').count() == 1
    assert page.locator('#project-anatomy-state').count() == 1
    assert json.loads(page.locator('#project-anatomy-state').text_content()) == state
    for anchor in ANCHORS:
        assert page.locator(f'#{anchor}').count() == 1, anchor
        assert page.locator(f'nav a[href="#{anchor}"]').count() == 1, anchor
    assert page.locator('#audit > details').count() >= 8
    assert page.locator('#audit table').count() >= 3
    assert page.locator('table th:not([scope="col"])').count() == 0
    result = page.evaluate('''() => {
        const ids = [...document.querySelectorAll('[id]')].map(e => e.id);
        const missing = [...document.querySelectorAll('a[href^="#"]')]
            .map(a => a.getAttribute('href').slice(1)).filter(id => !document.getElementById(id));
        const overflow = [...document.querySelectorAll('main *')].filter(e => {
            const r = e.getBoundingClientRect();
            return r.width && r.height && !e.closest('#audit') && e.scrollWidth > e.clientWidth + 2
                && !['SPAN', 'A', 'B', 'STRONG', 'CODE', 'SMALL'].includes(e.tagName);
        }).map(e => ({tag:e.tagName, id:e.id, cls:e.className, width:e.clientWidth, scroll:e.scrollWidth}));
        return {unique:new Set(ids).size === ids.length, missing, overflow,
            page:document.documentElement.scrollWidth, viewport:document.documentElement.clientWidth,
            hero:document.querySelector('.hero').getBoundingClientRect().height,
            nav:document.querySelector('nav').getBoundingClientRect().height};
    }''')
    assert result['unique'], 'Duplicate IDs'
    assert not result['missing'], result['missing']
    assert result['page'] <= result['viewport'] + 2, result
    assert not result['overflow'], result['overflow']
    assert result['nav'] <= 120, result
    return result


def capture(reports, output, before=None, pdf=True):
    output.mkdir(parents=True, exist_ok=True)
    receipt = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for report in reports:
            state = validate_report(report)
            for width in WIDTHS:
                ctx = browser.new_context(viewport={'width': width, 'height': 900 if width > 390 else 844}, java_script_enabled=False)
                page = ctx.new_page()
                remote = []
                page.on('request', lambda req: remote.append(req.url) if req.url.startswith(('http:', 'https:')) else None)
                page.goto(report.as_uri(), wait_until='load')
                measured = structural(page, state)
                assert not remote, remote
                name = f'{report.stem}-after-{width}'
                page.screenshot(path=str(output / (name + '.png')), full_page=True)
                page.screenshot(path=str(output / (name + '-first-screen.png')))
                page.locator('#artifact-inventory > summary').click()
                page.locator('#evidence-ledger > summary').click()
                assert page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth + 2')
                for region in page.locator('#audit .table-scroll').all():
                    assert region.get_attribute('tabindex') == '0'
                if width == 390 and report.stem == 'scan-on-scan':
                    page.locator('#evidence-ledger').scroll_into_view_if_needed()
                    page.screenshot(path=str(output / 'scan-on-scan-audit-390.png'))
                receipt.append({'report': report.name, 'width': width, **measured, 'network_requests': len(remote)})
                ctx.close()
            ctx = browser.new_context(viewport={'width': 1280, 'height': 900}, java_script_enabled=False)
            page = ctx.new_page()
            page.goto(report.as_uri())
            page.keyboard.press('Tab')
            assert page.locator('.skip-link').evaluate('(e)=>e===document.activeElement')
            page.locator('#evidence-ledger > summary').focus()
            assert page.locator('#evidence-ledger > summary').evaluate('(e)=>getComputedStyle(e).outlineStyle') != 'none'
            page.keyboard.press('Enter')
            assert page.locator('#evidence-ledger').get_attribute('open') is not None
            page.goto(report.as_uri())
            if state['evidence']:
                evidence_id = state['evidence'][0]['id']
                page.goto(report.as_uri() + '#e-' + evidence_id)
                page.wait_for_function('document.querySelector("#evidence-ledger").open')
                assert page.locator('[id=' + json.dumps('e-' + evidence_id) + ']').is_visible()
            if pdf and report.stem in ('scan-on-scan', 'many-findings', 'long-identifiers'):
                page.goto(report.as_uri())
                page.emulate_media(media='print')
                # Print CLOSED details via CSS; do not silently open them using DOM automation.
                assert page.locator('#evidence-ledger').get_attribute('open') is None
                assert page.locator('.metric-grid').first.evaluate('(e)=>getComputedStyle(e).display') == 'grid'
                assert page.locator('.table-checks td').first.evaluate('(e)=>getComputedStyle(e).display') == 'block'
                page.pdf(path=str(output / (report.stem + '-after.pdf')), format='A4', print_background=True)
                assert page.locator('#evidence-ledger table').evaluate('(e)=>e.getBoundingClientRect().height') > 0
                page.screenshot(path=str(output / (report.stem + '-print.png')))
            ctx.close()
        if before:
            for width in WIDTHS:
                ctx = browser.new_context(viewport={'width': width, 'height': 900 if width > 390 else 844}, java_script_enabled=False)
                page = ctx.new_page()
                page.goto(before.as_uri())
                page.screenshot(path=str(output / f'scan-on-scan-before-{width}.png'), full_page=True)
                page.screenshot(path=str(output / f'scan-on-scan-before-{width}-first-screen.png'))
                ctx.close()
        browser.close()
    (output / 'browser-receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(f'PASS: {len(receipt)} report/viewport combinations; native keyboard, deep links and print checked. Captures: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', type=Path, nargs='+')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--before', type=Path)
    parser.add_argument('--no-pdf', action='store_true')
    args = parser.parse_args()
    capture([path.resolve() for path in args.reports], args.output.resolve(), args.before.resolve() if args.before else None, not args.no_pdf)
