Bugfixes:

- Properly set `secret/handshake` on first request instead of returning hardcoded values
- Changed logging to report errors back via the request and prevented the process from exiting/crashing on error
- Fixed `ls` to properly display only single level keys
- Fixed `tree` to properly recurse more than a single level
- Fixed `mounts` such that they return properly based on top-level keys in credhub