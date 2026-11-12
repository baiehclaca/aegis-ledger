import asyncio,sys
from playwright.async_api import async_playwright
PAGES=["","government/","open-source/","technology/","whitepaper/","security/","contact/"]
async def main():
  async with async_playwright() as p:
    br=await p.chromium.launch(executable_path='/usr/bin/google-chrome')
    for w,h,tag in [(1440,900,'desktop'),(390,844,'mobile')]:
      ctx=await br.new_context(viewport={'width':w,'height':h},device_scale_factor=1)
      for pg_ in PAGES:
        pg=await ctx.new_page()
        await pg.goto('http://127.0.0.1:4190/'+pg_,wait_until='networkidle')
        # scroll through to trigger reveals
        H=await pg.evaluate('document.body.scrollHeight')
        for y in range(0,H,400):
          await pg.evaluate(f'window.scrollTo(0,{y})'); await pg.wait_for_timeout(60)
        await pg.evaluate('window.scrollTo(0,0)'); await pg.wait_for_timeout(2600)
        name=(pg_.strip('/') or 'home')
        await pg.screenshot(path=f'shots/{name}-{tag}.png',full_page=True)
        await pg.screenshot(path=f'shots/{name}-{tag}-fold.png')
        ov=await pg.evaluate('[...document.querySelectorAll("*")].filter(e=>e.getBoundingClientRect().right>window.innerWidth+1).map(e=>e.tagName+"."+e.className).slice(0,5)')
        if ov: print(name,tag,'OVERFLOW',ov)
        await pg.close()
      await ctx.close()
    await br.close()
asyncio.run(main())
