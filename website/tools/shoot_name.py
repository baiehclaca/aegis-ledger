import asyncio
from playwright.async_api import async_playwright
async def m():
  async with async_playwright() as p:
    b=await p.chromium.launch(executable_path='/usr/bin/google-chrome')
    for w,h,tag in [(1440,900,'desktop'),(390,844,'mobile')]:
      pg=await b.new_page(viewport={'width':w,'height':h})
      await pg.goto('http://127.0.0.1:4190/',wait_until='networkidle')
      H=await pg.evaluate('document.body.scrollHeight')
      for y in range(0,H,400):
        await pg.evaluate(f'window.scrollTo(0,{y})'); await pg.wait_for_timeout(60)
      await pg.wait_for_timeout(1500)
      await pg.locator('#name').screenshot(path=f'shots/home-name-{tag}.png')
      await pg.close()
    await b.close()
asyncio.run(m())
