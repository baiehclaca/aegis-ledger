# Regenerates public/og.png (1200x630) from tools/og.html. Run: python3 tools/og.py
import asyncio, pathlib
from playwright.async_api import async_playwright
async def m():
  async with async_playwright() as p:
    b=await p.chromium.launch(executable_path='/usr/bin/google-chrome')
    pg=await b.new_page(viewport={'width':1200,'height':630})
    await pg.goto('file://'+str(pathlib.Path('tools/og.html').resolve())); await pg.wait_for_timeout(300)
    await pg.screenshot(path='public/og.png'); await b.close()
asyncio.run(m())
