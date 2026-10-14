"""Check Beat navigation, internal links and mobile layout using existing Chromium."""
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
    page.get_by_role('link',name='Curated verifiers',exact=True).click()
    page.wait_for_url('**/verifiers.html')
    assert page.locator('section').count()==9
    assert page.locator('#chutes').inner_text().find('GPU evidence is not appraised')>=0
    page.screenshot(path=str(out/'directory-desktop.png'),full_page=True)
    page.get_by_role('link',name='Stage criteria',exact=True).click()
    page.wait_for_url('**/stages.html')
    assert 'no stages awarded' in page.locator('main').inner_text()
    page.screenshot(path=str(out/'stages-desktop.png'),full_page=True)
    for name in ['verifiers.html','stages.html','index.html']:
        page.set_viewport_size({'width':390,'height':844})
        page.goto((docs/name).as_uri(),wait_until='networkidle')
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth'),name
        page.screenshot(path=str(out/(name+'.mobile.png')),full_page=True)
    browser.close()
(out/'beat-browser-results.json').write_text(json.dumps({'directory_providers':9,'navigation':True,'all_internal_links_valid':True,'mobile_no_overflow':True,'stage_proposal_no_awards':True},indent=2)+'\n')
print('Beat browser and all generated internal links passed.')
