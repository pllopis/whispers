# CHANGELOG

<!-- version list -->

## v0.3.0 (2026-02-23)

### Bug Fixes

- Add helm/whispers/Chart.yaml to semantic-release assets so it is committed as part of the release
  ([`22c2a09`](https://github.com/pllopis/whispers/commit/22c2a097d93e4a2eb2fca1399db314c0114c61e3))

- Remove egg-info
  ([`df6e35e`](https://github.com/pllopis/whispers/commit/df6e35ef68690bd36ad8b970156a8f708c0171c8))

### Features

- Add .env.example
  ([`9e6c1da`](https://github.com/pllopis/whispers/commit/9e6c1dacd348af5b5dc1e0ee2bb91fac23f773fb))

- Add app version to footer
  ([`ac478e6`](https://github.com/pllopis/whispers/commit/ac478e6c5a5a3c5266e2eb45c8d8ea01651c1d79))

- Implement conventional commits based version bumping via python-semantic-release
  ([`1e0bf0b`](https://github.com/pllopis/whispers/commit/1e0bf0b4b87eec8fb77e3efe91ff515d40e9e08f))


## v0.2.1 (2026-02-23)

### Bug Fixes

- Convert DISABLE_GROUPS to boolean for correct handling
  ([`e8c846a`](https://github.com/pllopis/whispers/commit/e8c846af5defcee4495e2587b41a2d952c5a4045))


## v0.2.0 (2026-02-23)

### Bug Fixes

- Always call the userinfo endpoint
  ([`c89c5cc`](https://github.com/pllopis/whispers/commit/c89c5cce01a182f48f58534cc25b4f4bbb147e05))

- Docker-compose health check
  ([`2e145e9`](https://github.com/pllopis/whispers/commit/2e145e9da0d9943dd8de7ccd4b811c4e03be38d5))

- Redirect to previous location after logging in
  ([`e0444e6`](https://github.com/pllopis/whispers/commit/e0444e6c857a368e59ed69246dc102dbe8382e4e))

### Features

- Add copy secret shortcut button
  ([`fea2c29`](https://github.com/pllopis/whispers/commit/fea2c295c01a72ff00002fe070f8f2d6dc80c21e))

- Automatically add whisper author to allowed_users unless the secret is "open"
  ([`89f743f`](https://github.com/pllopis/whispers/commit/89f743f1177abe82bf6b19525a18169292083eb4))

- Make docker-compose host port configurable via HOST_PORT
  ([`2b533ba`](https://github.com/pllopis/whispers/commit/2b533ba0531a2f1562fe13f72cb3af98d56ab11b))

- Support hiding allowed groups field
  ([`adc61cb`](https://github.com/pllopis/whispers/commit/adc61cbd870c7e68374f7f592715abb662dfa2d4))

- **helm**: Default to the image matching the chart's appversion
  ([`e91524d`](https://github.com/pllopis/whispers/commit/e91524daa3fdd3fa015e53598efe19915cf39835))

- **helm**: Support overriding deployment update strategy
  ([`261469e`](https://github.com/pllopis/whispers/commit/261469ead193edaf60ce4687eeb8c80b17a4f920))


## v0.1.1 (2025-10-02)

### Features

- Add docker-compose.yaml
  ([`a3e63eb`](https://github.com/pllopis/whispers/commit/a3e63eb6a0b5b7df0c48e8deab8f697e8e6f47c9))

- Improve docs of environment variables
  ([`dbaad6a`](https://github.com/pllopis/whispers/commit/dbaad6acf48f8af2f5be65e0eb107b865c92639f))

- Support specifying user ids or emails
  ([`5a006f6`](https://github.com/pllopis/whispers/commit/5a006f614c5b1c8d04d9fb2fd2607514f4a33cfb))


## v0.1.0 (2025-09-23)

- Initial Release
