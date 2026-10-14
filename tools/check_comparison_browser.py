"""Browser checks for the compact comparison, evidence navigation and route grouping.

Uses an existing system Chromium/Playwright installation; no dependency download.
"""
import argparse
import json
from pathlib import Path
from urllib.parse import unquote, urlsplit
from html.parser import HTMLParser

from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--docs', type=Path, default=Path('docs'))
    parser.add_argument('--output', type=Path, default=Path('local-data/comparison-review'))
    args = parser.parse_args()
    docs, out = args.docs.resolve(), args.output
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as w:
        browser = w.chromium.launch(executable_path='/usr/bin/chromium', headless=True, args=['--no-sandbox'])
        page = browser.new_page(viewport={'width':1440, 'height':1000})
        page.goto((docs/'index.html').as_uri(), wait_until='networkidle')
        assert page.locator('.provider-row').count() == 9
        assert page.locator('.route-row:visible').count() == 0
        top = page.locator('table').bounding_box()['y']
        heights = page.locator('.provider-row').evaluate_all('(es)=>es.map(e=>e.getBoundingClientRect().height)')
        assert top < 250 and max(heights) <= 44
        assert page.locator('.assessment-scroll').bounding_box()['height'] < 500
        page.screenshot(path=str(out/'overview.png'), full_page=True)
        button = page.locator('tbody[data-provider="near-ai"] .provider-toggle')
        button.focus();page.keyboard.press('Enter')
        assert page.locator('#routes-near-ai .route-row:visible').count() == 3
        page.screenshot(path=str(out/'near-expanded.png'), full_page=True)
        href = './assessments.html#near-ai-gateway-e2ee-session'
        page.locator(f'a[href="{href}"]').click()
        page.wait_for_url('**/assessments.html#near-ai-gateway-e2ee-session')
        target=page.locator('#near-ai-gateway-e2ee-session')
        target.wait_for();assert target.evaluate('(e)=>e.open')
        assert 'response-key substitution' in target.inner_text()
        target.screenshot(path=str(out/'session-evidence.png'))
        page.goto((docs/'index.html').as_uri(), wait_until='networkidle')
        page.locator('tbody[data-provider="tinfoil"] .signal').first.click()
        page.wait_for_url('**/assessments.html#provider-tinfoil-hardware')
        assert 'limitation of our instrument' in page.locator('#provider-tinfoil-hardware').inner_text()
        page.goto((docs/'index.html').as_uri(), wait_until='networkidle')
        page.locator('#expand-all').click()
        assert page.locator('.route-row:visible').count() == 19
        page.select_option('#provider-filter', 'aci-gateway')
        assert page.locator('.provider-row:visible').count() == 1
        assert page.locator('.route-row:visible').count() == 3
        page.locator('.history-link:visible').click()
        page.wait_for_url('**/history.html?provider=aci-gateway')
        assert page.locator('#provider').input_value() == 'aci-gateway'
        page.locator('#chart svg').wait_for()
        page.goto((docs/'index.html').as_uri(), wait_until='networkidle')
        page.set_viewport_size({'width':390,'height':844})
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
        first=page.locator('.provider-row td').first
        before=first.bounding_box()['x']
        page.locator('.assessment-scroll').evaluate('(e)=>e.scrollLeft=500')
        assert abs(first.bounding_box()['x']-before)<2
        page.screenshot(path=str(out/'mobile.png'), full_page=True)
        nojs=browser.new_page(java_script_enabled=False)
        nojs.goto((docs/'index.html').as_uri())
        assert nojs.locator('.route-row:visible').count() == 19
        browser.close()
    # Validate every internal assessment/history/measurement destination and fragment.
    class Links(HTMLParser):
        def __init__(self):super().__init__();self.ids=set();self.hrefs=[]
        def handle_starttag(self, tag, attrs):
            a=dict(attrs)
            if 'id' in a:self.ids.add(a['id'])
            if tag=='a' and 'href' in a:self.hrefs.append(a['href'])
    parsed={}
    for p in docs.glob('*.html'):
        obj=Links();obj.feed(p.read_text());parsed[p.name]=obj
    for name in ['index.html','assessments.html','measurements.html']:
        for href in parsed[name].hrefs:
            u=urlsplit(href)
            if u.scheme or u.netloc:continue
            target=Path(u.path).name if u.path else name
            if target not in parsed:continue
            if u.fragment:assert unquote(u.fragment) in parsed[target].ids,(name,href)
    (out/'browser-results.json').write_text(json.dumps({'provider_rows':9,'route_rows':19,'row_heights':heights,'table_top':top,'keyboard_expansion':True,'assessment_links':True,'provider_history_filter':True,'mobile_sticky_identity':True,'no_js_routes_visible':True,'internal_fragments_valid':True},indent=2)+'\n')
    print('Comparison browser checks passed.')


if __name__=='__main__':main()
