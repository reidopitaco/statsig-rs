Statsig client
==============

Unofficial lib to interact with statsig.io. It's still an early WIP version, but is already capable of handling some checks with cache and delegate other scenarios to an HTTP request to the API.

Implements the logic described for their [Server SDKs](https://docs.statsig.com/server/introduction).

SDK logic
---------
1. Initialize the SDK
  a. Fetch initial configurations from the server.
  b. Start periodic task to refresh configurations (every 10s)
  c. Start periodic task to emit logs about exposures (every 60s)
2. Experiment checking
