# Distribution migration compatibility

Back up the database, run the normal migration runner, then start matching API and worker versions. The runner preserves applied migration identities and SQL, including recognized preview histories, and appends missing migrations without rewriting history. It stops on an unrecognized or inconsistent ledger; investigate it rather than inserting or renumbering rows manually.

Migration 97 invalidates existing distribution authorizations. Obtain fresh independent review after upgrading; removing and restoring a reviewer does not revive old approval. Upgrade agents alongside the matching server when enabling supported features. Capability gates remain authoritative: applying migrations does not enable Azure storage, shared Windows/IIS material deployment, independent Linux staging or exact-version cleanup.
