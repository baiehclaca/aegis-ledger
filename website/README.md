# Silver Grey Ledger website

Next.js 15 static export for https://silvergreyhound.github.io/silver-grey-ledger/.

```
pnpm install
pnpm dev                    # http://localhost:3000
pnpm build                  # local preview build, empty base path, static site in out/
GITHUB_PAGES=true pnpm build                         # Pages build, base path /silver-grey-ledger
NEXT_PUBLIC_BASE_PATH=/silver-grey-ledger pnpm build # same, explicit
```

Product name: `PRODUCT_NAME` in `lib.ts`.
Contact email: set `CONTACT_EMAIL` in `lib.ts` when chosen.
