# connect-ui

React application for Pearl Connect (BYOA).
Served by the [pearl-connect](https://github.com/valory-xyz/pearl-connect) agent binary at `http://127.0.0.1:8716` and embedded by [Pearl](https://github.com/valory-xyz/olas-operate-app) via iframe.

## Development

```bash
# Copy env file first
cp apps/connect-ui/.env.example apps/connect-ui/.env

yarn nx dev connect-ui       # http://localhost:4500
yarn nx build connect-ui
yarn nx test connect-ui
yarn nx lint connect-ui
```

## Environment variables

| Variable          | Values            | Effect                                  |
| ----------------- | ----------------- | --------------------------------------- |
| `IS_MOCK_ENABLED` | `true` \| `false` | Use mock data instead of live API calls |

## 📦 Release process

1. Bump the version in `package.json`
2. Push a new tag with the `-connect` suffix (e.g., `v1.0.0-connect`)
3. The CI will build and release the contents of the `dist/apps/connect-ui` directory as `connect-ui-build.zip` on a GitHub Release

The [pearl-connect](https://github.com/valory-xyz/pearl-connect) binary consumes the zip: its server looks for the unpacked bundle in `pearl_connect/assets/ui` (`ui_build_dir()`) and serves it at `GET /`. Pearl pins the UI release tag in `frontend/constants/serviceTemplates/agentUiReleases.ts` in [olas-operate-app](https://github.com/valory-xyz/olas-operate-app).
