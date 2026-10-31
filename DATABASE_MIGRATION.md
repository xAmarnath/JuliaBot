# MongoDB migration

The VPS Julia bot data was migrated to `Main_Database` on 2026-10-05.

| Source | Destination collection | Verified entries |
| --- | --- | ---: |
| `database.db` | `records` | 635 |
| `julia.db` | `records` | 2 alerts and their parent record |
| `stickers.db` | `legacy_stickers_records` | 15 |

Entry counts include nested bucket metadata. Keys, values, hierarchy, and sequence counters were preserved. The legacy sticker schema is archived separately; active sticker data comes from `database.db`.

Every imported record was read back and compared with its source. Canonical SHA-256 digests matched:

- `records` (638 entries): `6afc9a95c8a358cbf6611c37e24cc34a0243d288bdb2116595a0afb4859790d3`
- `legacy_stickers_records` (15 entries): `b3c6d331c7043931128b4ce291e66f152122ef27d89436cff8f5c5e9d86842a3`

These digests describe the migration snapshot; normal bot activity changes live records afterward. Existing conflicting destination records were not overwritten.

Private source backups remain on the VPS at `/home/ubuntu/gogram-premium-audit/db-backup`. The SQLite backup used SQLite's backup API. Source databases were not deleted. Migration tooling remains at `/home/ubuntu/gogram-premium-audit/mongo-migrate` and is separate from the bot's runtime dependencies.

The bot now requires `MONGODB_URI`; `MONGODB_DATABASE` defaults to `Main_Database`. MongoDB database names cannot contain spaces. The runtime has no BoltDB or SQLite dependency. MongoDB transaction rollback, binary key ordering, nested deletion, and concurrent sequence updates were tested against the hosted database using an isolated temporary collection, which was removed afterward.

## Runtime memory cache

The records collection is loaded once at startup. Read transactions use memory; writes are published to memory only after a MongoDB transaction commits. Use one bot process and restart it after external database edits. An uncertain commit result blocks further cached access until restart. Game state is saved every 15 seconds and on graceful shutdown; failed saves retain pending changes.
