# HeteroNetwork Console

Static console for a deployed HeteroNetwork lab.

Serve this directory with any static HTTP server. The page loads `state.json`
from the same directory and falls back to the embedded sample state when the
file is missing.

```sh
python3 -m http.server 18088 --bind 0.0.0.0 --directory console
```

`state.json` is intentionally deployment-local because it contains live sandbox
IDs, IPs, node IDs, and reachability results.
