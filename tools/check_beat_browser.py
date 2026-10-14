"""Check Beat assessment/history navigation, internal links and mobile layout using existing Chromium."""
import argparse
import json
from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import urlsplit, unquote
from playwright.sync_api import sync_playwright
parser=argparse.ArgumentParser()
parser.add_argument('--docs', type=Path, default=Path('docs'))
parser.add_argument('--output', type=Path, default=Path('local-data/beat-review'))
args=parser.parse_args()
docs=args.docs.resolve();out=args.output;out.mkdir(parents=True,exist_ok=True)
class Links(HTMLParser):
    def __init__(self):super().__init__();self.ids=set();self.links=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if 'id' in a:self.ids.add(a['id'])
        if tag=='a' and 'href' in a:self.links.append(a['href'])
parsed={}
for p in docs.glob('*.html'):
    obj=Links();obj.feed(p.read_text());parsed[p.name]=obj
for name,obj in parsed.items():
    for href in obj.links:
        u=urlsplit(href)
        if u.scheme or u.netloc:continue
        target=(docs/u.path).resolve() if u.path else docs/name
        assert target.is_file(),(name,href)
        if u.fragment and target.name in parsed:assert unquote(u.fragment) in parsed[target.name].ids,(name,href)
with sync_playwright() as w:
    browser=w.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1440,'height':1000})
    page.goto((docs/'index.html').as_uri(),wait_until='networkidle')
    assert page.locator('a[href="./verifiers.html"]').count() == 0
    assert not (docs/'verifiers.html').exists()
    assert not (docs/'verifiers.json').exists()
    primary=page.locator('nav[aria-label="Primary"]')
    assert primary.locator('a').count() == 2
    assert primary.locator('a[aria-current="page"]').get_attribute('href') == './index.html'
    primary.locator('a[href="./history.html"]').click()
    page.wait_for_url('**/history.html')
    page.locator('#chart svg').wait_for()
    assert page.locator('.reference-key dt').all_text_contents() == ['Expected reference','Observed identity','Document fingerprint']
    page.locator('details.explainer summary').click()
    assert 'Maple publishes PCR0' in page.locator('details.explainer').inner_text()
    primary=page.locator('nav[aria-label="Primary"]')
    assert primary.locator('a').count() == 2
    assert primary.locator('a[aria-current="page"]').get_attribute('href') == './history.html'
    page.screenshot(path=str(out/'reference-values-desktop.png'),full_page=True)
    primary.locator('a[href="./index.html"]').click()
    page.wait_for_url('**/index.html')
    page.locator('a[href="./stages.html"]').first.click()
    page.wait_for_url('**/stages.html')
    assert 'no stages awarded' in page.locator('main').inner_text()
    page.screenshot(path=str(out/'stages-desktop.png'),full_page=True)
    for name in ['stages.html','index.html','history.html']:
        page.set_viewport_size({'width':390,'height':844})
        page.goto((docs/name).as_uri(),wait_until='networkidle')
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth'),name
        page.screenshot(path=str(out/(name+'.mobile.png')),full_page=True)
    browser.close()
(out/'beat-browser-results.json').write_text(json.dumps({'verifier_directory_repo_only':True,'two_primary_tabs':True,'all_internal_links_valid':True,'mobile_no_overflow':True,'stage_proposal_no_awards':True},indent=2)+'\n')
print('Beat browser and all generated internal links passed.')
