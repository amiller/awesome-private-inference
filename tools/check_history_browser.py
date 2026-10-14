"""Exercise the real graph and export a script-free, shareable HTML snapshot.

Run with an existing Python/Playwright and Chromium installation; no npm install.
The snapshot uses native disclosure controls because the artifact host blocks JS.
"""
from pathlib import Path
import json
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "local-data/history-preview"
OUT.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path="/usr/bin/chromium", args=["--no-sandbox"])
    page = browser.new_page(viewport={"width": 1440, "height": 1200})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto((ROOT / "docs/history.html").as_uri())
    page.wait_for_selector("svg .mark")
    assert page.locator("#inventory tr").count() > 0
    page.screenshot(path=str(OUT / "overview.png"))
    page.select_option("#provider", "near-ai")
    page.select_option("#group", "component")
    page.locator("svg .mark").last.click()
    assert "Captured evidence" in page.locator("#details").inner_text()
    page.screenshot(path=str(OUT / "near-detail.png"))
    page.select_option("#provider", "maple")
    page.select_option("#family", "published reference set")
    assert page.locator("#inventory tr").count() > 0
    page.select_option("#size", "text")
    page.locator("svg .mark").first.focus()
    page.keyboard.press("Enter")
    assert "reference events" in page.locator("#details").inner_text() or "First retained capture" in page.locator("#details").inner_text()
    page.select_option("#provider", "venice")
    assert page.locator("#inventory tr").count() == 0
    page.select_option("#provider", "")
    page.select_option("#family", "")
    page.select_option("#group", "provider")
    page.select_option("#size", "entries")
    page.fill("#search", "PCR")
    assert 0 < page.locator("#inventory tr").count() < 20
    page.fill("#search", "")
    with page.expect_download() as download:
        page.locator("#download").click()
    download.value.save_as(OUT / "plotted-data.json")
    assert json.loads((OUT / "plotted-data.json").read_text())["schema_version"] == 1
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.evaluate("scrollTo(0,0)")
    page.screenshot(path=str(OUT / "mobile.png"))
    page.set_viewport_size({"width": 1440, "height": 1200})
    assert not errors, errors
    # Freeze the actual rendered graph. Native links/disclosures remain usable
    # without scripts; don't leave nonfunctional filter controls in the preview.
    page.evaluate("""() => {
      const section=node('section',undefined,'card');section.id='change-evidence';
      section.append(node('h2','Change evidence'),node('p','Select a graph point to jump to its event, then expand the reference entry. This shareable snapshot uses native disclosures; filtering and circle-size controls are available in the repository page.','note'));
      for(const e of D.events){inspect(e);const detail=$('details').cloneNode(true);detail.removeAttribute('id');detail.className='';
        const disclosure=node('details');disclosure.id='event-'+e.id;
        disclosure.append(node('summary',`${e.at.slice(0,10)} · ${e.provider} · ${L.get(e.lane).component} / ${L.get(e.lane).field} · ${e.kind}`),detail);section.append(disclosure);}
      document.querySelector('.limits').before(section);
      for(const c of document.querySelectorAll('svg .mark')){const ids=c.dataset.eventIds.split(',');const a=svgEl('a',{href:'#event-'+ids[0]});c.before(a);a.append(c);c.removeAttribute('role');c.removeAttribute('tabindex');}
      document.querySelector('.controls').replaceWith(node('p','Preview: all providers and layers · circle size = reference entries changed. Follow graph links or expand full values below.','note'));
      const trs=[...document.querySelectorAll('#inventory tr')];D.lanes.forEach((l,i)=>{const b=trs[i].querySelector('button'),a=node('a','Inspect latest event ↓');a.href='#event-'+l.events.at(-1);b.replaceWith(a)});
      $('details').remove();document.querySelector('.layout').style.gridTemplateColumns='1fr';
      $('download').remove();document.querySelector('header a').href='https://amiller.github.io/awesome-private-inference/';
      document.querySelector('footer').append(node('p','Unlisted visual preview. Anyone holding the link can view it. Generated from real repository captures; no provider inference was performed for this visualization.'));
      document.querySelectorAll('script').forEach(s=>s.remove());
    }""")
    (OUT / "reference-history-preview.html").write_text(page.content())
    page.goto((OUT / "reference-history-preview.html").as_uri())
    page.locator("svg a").first.click()
    assert "#event-" in page.url
    target = page.locator("#" + page.url.split("#", 1)[1])
    target.locator(":scope > summary").click()
    assert target.get_attribute("open") is not None
    page.goto((OUT / "reference-history-preview.html").as_uri())
    page.screenshot(path=str(OUT / "shared-preview.png"))
    browser.close()
print("Graph filters, selection, keyboard, search, JSON download, mobile layout and script-free snapshot links passed")
