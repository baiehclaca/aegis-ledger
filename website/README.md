# Aegis Ledger website

Next.js 15 static export for https://baiehclaca.github.io/aegis-ledger/.

```
pnpm install
pnpm dev                                         # http://localhost:3000
NEXT_PUBLIC_BASE_PATH=/aegis-ledger pnpm build   # static site in out/
```

Deployed by `.github/workflows/pages.yml` on pushes to `main` that change `website/**`.
Contact email: set `CONTACT_EMAIL` in `lib.ts` when chosen.
