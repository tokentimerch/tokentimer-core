# ADR-0013: Multiple contact groups per asset

## Status

Accepted (2026-09-15). Amended 2026-09-16: schema, backfill, dual-write,
plural API/UI, and alert/digest plural reads ship together. Multi-group
writes are **on by default** (unset / empty). Set
`CONTACT_GROUP_PLURAL_WRITES=false` only as a mixed-fleet kill switch
during a rolling upgrade.

## Context

Each token (including certificates) and each CertOps agent stores one
`TEXT` `contact_group_id`. Groups themselves are not rows: they live as
elements of `workspace_settings.contact_groups` (JSONB). `NULL` on the
asset means "use `workspace_settings.default_contact_group_id`" at send
time. `resolveContactGroup` picks that single id, then that group's
`thresholds[]` (or the workspace default) and that group's channels.

Operators want more than one group on the same asset. Today's workaround
is stuffing every recipient into one group, which couples thresholds,
digest flags, and membership that should stay separate.

The weekly digest makes the overlap problem concrete. It iterates
groups independently, loads assets assigned to that group (or unassigned
assets when the group is the workspace default), and sends. A recipient
who sits in two groups gets two messages. A suppress-the-second-copy
log keyed on recipient would "fix" the duplicate by dropping the second
group's assets, which is data loss: Alice in group A `{X, Y}` and group
B `{Z}` would receive only one group's set.

This record is about membership, resolution, delivery deduplication, and
digest aggregation. It does not change ADR-0009's durable-outbox rule
(intent is recorded in the deciding transaction; delivery is a later
drain). It also does not normalize `contact_groups` JSONB into relational
group tables.

## Decision

1. **Additive join tables. JSONB groups stay.**

   Contact-group *definitions* remain `workspace_settings.contact_groups`
   JSONB. Membership becomes many-to-many on two join tables. There is
   no `PRIMARY` flag and no ordered-membership column.

   `tokens.id` is already the primary key. Add a helper unique so a
   composite FK can pin a join row to one workspace's token, the same
   pattern as `certops_agents.uq_certops_agents_workspace_id`:

   ```
   ALTER TABLE tokens
     ADD CONSTRAINT uq_tokens_workspace_id UNIQUE (workspace_id, id);
   ```

   `token_contact_groups`:

   - columns: `token_id`, `workspace_id`, `contact_group_id`, `created_at`
   - `PRIMARY KEY (token_id, contact_group_id)`
   - `FOREIGN KEY (workspace_id, token_id) REFERENCES tokens (workspace_id, id) ON DELETE CASCADE`
   - `FOREIGN KEY (workspace_id) REFERENCES workspaces (id) ON DELETE CASCADE`
   - index `(workspace_id, contact_group_id, token_id)`

   `certops_agent_contact_groups`, same shape against
   `certops_agents (workspace_id, id)`:

   - columns: `agent_id`, `workspace_id`, `contact_group_id`, `created_at`
   - `PRIMARY KEY (agent_id, contact_group_id)`
   - `FOREIGN KEY (workspace_id, agent_id) REFERENCES certops_agents (workspace_id, id) ON DELETE CASCADE`
   - `FOREIGN KEY (workspace_id) REFERENCES workspaces (id) ON DELETE CASCADE`
   - index `(workspace_id, contact_group_id, agent_id)`

   `certops_agent_contact_groups.agent_id` references
   `certops_agents.id` (the row UUID), **not** `certops_agents.agent_id`
   (the wire identifier). Getting this FK wrong is a silent isolation
   hole.

   Backfill copies each non-null, non-empty singular `contact_group_id`
   into one join row. A `NULL` (or empty) singular column produces **no**
   join rows; defaulting happens at resolve time, not by inserting the
   workspace default id. Backfill copies the stored value as-is, including
   ids that no longer exist in JSONB; decision 5 drops those at resolve
   time.

   Bootstrap tokens stay a single row (no join table). They carry
   `contact_group_ids` JSONB plus the lex-smallest `contact_group_id`
   mirror. On registration, that array is copied into
   `certops_agent_contact_groups` **and** into
   `certops_agents.contact_group_id`. An empty bootstrap array produces
   no join rows and a null agent singular column.

   Application `assertContactGroupIds` remains mandatory on every write
   that assigns ids. Group existence lives in JSONB, so a SQL FK cannot
   prove a `contact_group_id` is a current workspace group. Invalid ids
   are 400, including import paths. The helper unique and composite FKs
   prove workspace isolation of the *asset*, not existence of the group.

   When alert-settings save removes groups from the JSON array, extend
   the existing stale-clear: delete join rows whose `contact_group_id` is
   no longer in the array (tokens and agents), then recompute each
   affected asset's singular column with the rule in decision 3. Resolve
   time (decision 5) still drops stale ids even if a row was not cleaned
   up yet.

2. **Dual-write rollout. This record does not stop writing singular columns.**

   Sequence, and not another order:

   1. Expand schema and backfill join rows from singular columns.
   2. Every writer dual-writes (join table plus singular compatibility
      mirror) via `replaceAssetContactGroups` (decision 7).
   3. Switch alert and digest **readers** to the join table
      (`resolveContactGroupsForAsset`, decision 5).
   4. Ship the plural API field and UI (`contact_group_ids` /
      `contactGroupIds`).
   5. A later change, not this one, stops writing the singular columns
      and then drops them.

   Those steps are two (plus a later drop) **deployable releases**, not
   commits in one binary. A rolling mix of pre-dual-write writers and
   join-table readers is the stale-join race this sequence exists to
   prevent: an old replica writes only `tokens.contact_group_id`, the
   join row stays at the backfilled value, and new workers send to the
   wrong group. Do not skip the dual-write release.

   The switch-reads release must re-backfill join rows from the singular
   column at migration start (repairing drift from a mixed dual-write
   window) **before** readers trust the join table and **before** the
   plural API can write two-or-more memberships. That rebuild starts
   with `LOCK TABLE ... IN SHARE ROW EXCLUSIVE MODE` on both join
   tables so dual-write `INSERT`/`UPDATE`/`DELETE` wait, while ordinary
   reads continue. `ON CONFLICT DO NOTHING` is still required: a writer
   that already holds a row lock can insert the same membership after
   the rebuild `DELETE` and before the rebuild `INSERT`. The lock is
   what stops a change or clear (A to B, or A to empty) from leaving a
   stale extra join row that switch-reads would then treat as
   authoritative. Canonical lex-smallest id uses UTF-8 byte order
   (`Buffer.compare` in Node, `COLLATE "C"` in PostgreSQL), not the
   database's default text collation and not JavaScript's default
   `.sort()`.

   Step 4 (two-or-more membership writes and dashboard multi-select) is
   gated by `CONTACT_GROUP_PLURAL_WRITES` (on unless set to `false` /
   `0` / `no`). This release's dashboard otherwise hits a still-running
   dual-write API with `[A,B]` and that replica persists only the
   singular companion. Keep the kill switch off (`false`) only while a
   mixed dual-write fleet remains; after every API, worker, and
   dashboard replica is this release, leave the variable unset (on).
   When the flag is off, a `contact_group_ids` / `contactGroupIds` write
   with two or more ids is HTTP 400. `GET /api/auth/features` reports
   `contactGroupPluralWrites` so the dashboard can stay single-select.

   Until step 5, `tokens.contact_group_id` and
   `certops_agents.contact_group_id` are a compatibility mirror of join
   membership, not an independent assignment. Readers that have not yet
   been switched may still consult the singular column. After step 3,
   join-table membership is the source of truth even if the mirror is
   wrong.

3. **Canonical legacy `contact_group_id` is the lexicographically smallest assigned id.**

   After any membership write, the singular column is:

   - the lexicographically smallest `contact_group_id` among the
     assigned join rows, using ordinary UTF-8/`TEXT` byte order on the
     id strings, or
   - `NULL` when there are no join rows.

   `GET` `contact_group_ids` (and CertOps `contactGroupIds`) is that
   same set sorted lexicographically. Reordering
   `workspace_settings.contact_groups` does **not** change any asset's
   stored singular id and does not rewrite join rows. There is no
   primary-group flag. The singular value is a projection for old
   clients, not an operator-chosen leader.

4. **Request semantics on every write endpoint.**

   Token/certificate routes keep snake_case (`contact_group_id`,
   `contact_group_ids`). CertOps agent and bootstrap routes keep
   camelCase (`contactGroupId`, `contactGroupIds`). Bootstrap tokens
   persist the same pair on the bootstrap row until registration.
   Semantics below apply to every endpoint that writes token, agent, or
   bootstrap membership, including import.

   Evaluate the plural field first:

   - **Both fields present:** `contact_group_ids` / `contactGroupIds`
     wins. The singular field is ignored for membership (no
     cross-check, no error if they disagree).
   - **`contact_group_ids: []`:** no explicit assignments; use the
     workspace default at resolve time. Delete all join rows for that
     asset and set the singular column `NULL`.
   - **Plural omitted on PUT/PATCH:** do not modify groups, even if
     other asset fields change. This is patch-like for membership on
     both verbs.
   - **Plural omitted and singular `null` or `""`:** clear explicit
     assignments (same stored result as `[]`). This tightens today's
     token PUT, which ignores JSON `null` for `contact_group_id` and
     only clears on `""`.
   - **Plural omitted and singular a non-null, non-empty id:** set
     membership to exactly that one id (one join row; singular equals
     that id).
   - **POST/create with both omitted:** same as `[]` (no join rows,
     singular `NULL`, default at resolve time).
   - **Invalid ids** in the field that wins (or in the singular field
     when it is the one applied): HTTP 400 from `assertContactGroupIds`.
     Import paths use the same helper and the same 400. Duplicate ids
     in one request collapse to a set; order in the request body is not
     stored.

   CertOps agent alert-settings already reject a body that changes
   neither downtime flag nor contact group. `contactGroupIds` counts as
   a contact-group write. Omitting both singular and plural leaves
   membership unchanged (the downtime flag may still change).

5. **`resolveContactGroupsForAsset` after switch-reads.**

   Once alert and digest readers have switched (decision 2 step 3),
   join-table ids are the source of truth. The helper:

   1. Loads join-row `contact_group_id` values for the asset in that
      workspace.
   2. If **no join rows exist**, the resolved set is
      `[default_contact_group_id]` when that default is non-null.
      Do **not** also require the singular column to be `NULL`. An
      empty join table means default, even if the mirror still holds
      an id.
   3. Drops ids that are absent from current
      `workspace_settings.contact_groups` JSONB (stale JSON ids).
   4. If that drop empties a set that was non-empty *before* the drop,
      fall back to `[default_contact_group_id]` (when the default
      exists in JSONB). A mixed stale-plus-valid set keeps the valid
      ids only; it does not add the default.
   5. If the default itself is missing from JSONB, it is dropped like
      any other stale id. A fully empty result means no group: no
      channels, no digest candidates from this asset.

   **Thresholds (expiry windows).** Each resolved group's effective
   threshold list is its `thresholds[]` when that array is present and
   non-empty, otherwise the workspace `alert_thresholds`. Queue an
   expiry alert if **any** resolved group contains that window.
   `alert_key` remains one row per asset plus window: overlapping groups
   do not enqueue two queue rows for the same token and the same
   `threshold_days`.

   **Delivery** re-resolves current membership at send time, then keeps
   the groups whose effective list contains `alert_queue.threshold_days`.
   Union those groups' channels. Dedupe destinations by **normalized
   destination**, not by contact UUID:

   - email: lowercased, trimmed address
   - WhatsApp: E.164 phone
   - webhook: the delivery URL string

   Two `workspace_contacts` rows that share an email therefore receive
   one email. If re-resolution yields no group whose effective list
   contains the queued window, do not send and do not substitute "any
   remaining group".

   **Single-shot events** skip the window filter and union channels
   from every currently resolved group, still deduped by normalized
   destination. Single-shot means endpoint-monitor down and recovered,
   renewal failure, and agent health (down and recovered).

   After switch-reads, every alert/digest read site uses this helper
   (expiry queueing, `alert_queue` delivery, weekly digest, endpoint
   monitors, renewal-failure enqueue, agent-health enqueue). The
   singular `resolveContactGroup` is not the membership source of
   truth after that switch.

6. **Weekly digest is recipient-centric aggregation, not per-group send
   plus suppress.**

   Per workspace, per existing `week_start_date` (Monday 00:00 UTC,
   unchanged):

   1. Collect candidate assets **per digest-enabled group**. A group is
      digest-enabled when at least one of `weekly_digest_email`,
      `weekly_digest_whatsapp`, `weekly_digest_webhooks` is true. An
      asset is a candidate for that group when it has a join row for
      the group, **or** when it has **no** join rows and this group is
      `default_contact_group_id`. Do not use the singular column for
      this test after switch-reads.
   2. Invert to `(channel, normalized recipient) -> assets`. For each
      digest-enabled group, for each channel whose digest flag is true
      on **that** group, add that group's candidate assets onto each
      of that group's recipients on that channel. Assets from a group
      whose flag is off for the channel are not added, even if the
      recipient also belongs to that group.
   3. Send **one** digest per recipient / channel / week containing the
      unioned asset set. Do not send per group and then drop a copy.

   Claim and skip live in a new table, not in `weekly_digest_log`:

   ```
   weekly_digest_recipient_log (
     workspace_id,
     week_start_date,
     channel,          -- email | whatsapp | webhook
     recipient_key,    -- HMAC-SHA256 of the normalized destination
     status,           -- pending | sent
     attempt_count,
     lease_expires_at,
     ...
     UNIQUE (workspace_id, week_start_date, channel, recipient_key)
   )
   ```

   The claim **must** be atomic so two workers cannot both own the same
   key. Use `INSERT ... ON CONFLICT ... DO UPDATE ... WHERE` the row is
   `pending` and (`lease_expires_at` is null or in the past) `RETURNING`,
   or an equivalent `UPDATE ... WHERE` lease expired `RETURNING`. A
   `RETURNING` empty set means another worker holds a live lease or the
   row is already `sent`; the caller must not send. `sent` rows are
   never reclaimed. Expired leases reclaim `pending` rows.

   Duplicate suppression for overlapping groups is guaranteed by this
   invert-and-claim, not by a second log. `recipient_key` is HMAC-SHA256
   of the normalized destination (email, E.164 phone, or webhook URL),
   keyed by `WEEKLY_DIGEST_RECIPIENT_KEY` or else `SESSION_SECRET`. Do
   not persist the destination itself.

   Retry policy:

   - **WhatsApp:** exactly-once at the provider via idempotency key
     `weekly-digest:${workspace_id}:${week_start_date}:whatsapp:${hmac}`
     (`hmac` is HMAC-SHA256 of the E.164 phone, same secret as
     `recipient_key`). The key does **not** include a contact-group id
     (the current key that does would split one recipient across
     groups).
   - **Email and webhooks:** at-least-once across a send/commit crash
     window. A process that sends successfully and then fails before
     committing `status = 'sent'` will be reclaimed when the lease
     expires and may send again. Do not promise exactly-once for email
     or webhooks.
   - A failed send leaves `status = 'pending'`, increments
     `attempt_count`, and clears or expires the lease so a later pass
     can reclaim. The default Helm schedule is once per week (Monday
     09:00). That next run uses a new `week_start_date`, so it will
     not reclaim last week's expired `pending` row. Automatic retry
     therefore requires another digest pass **in the same week**
     (manual rerun, or a more frequent dispatcher). Extra runs are
     safe: `sent` rows are never reclaimed. Do not read the five-minute
     lease as a promise that the weekly cron will retry a failed
     recipient.

   Keep `weekly_digest_log` as an optional group-level audit write if
   useful. Do **not** `SELECT` it as a skip key. The unique
   `(workspace_id, contact_group_id, week_start_date)` index on that
   table is historical; it must not gate recipient-centric delivery.

7. **`replaceAssetContactGroups` is the only membership writer.**

   Every path that assigns token or agent groups calls this helper,
   including `Token.create` / `Token.update`, so integrations, admin
   import, and raw `INSERT INTO tokens` cannot dual-write the singular
   column and skip the join table. The helper runs in the **same
   transaction** as the parent write: a failed membership write aborts
   the asset write.

   It replaces the full membership set (delete-then-insert, or
   equivalent set-diff) and then sets the singular column to the
   lexicographically smallest assigned id, or `NULL` if empty
   (decision 3). Callers pass the already-validated id list from
   decision 4; the helper does not invent a different set.

   Registration is a writer: it calls the helper with the bootstrap
   token's `contactGroupIds` (empty list when none) while inserting
   `certops_agents`. Agent alert-settings updates go through the same
   helper. WhatsApp (or any other) group-rewrite that today
   `UPDATE`s `tokens.contact_group_id` in bulk must go through it as
   well, for both tokens and agents.

8. **Scope is tokens/certificates and CertOps agents.**

   Membership join tables exist only for `tokens` and `certops_agents`.
   Endpoint monitors have no contact-group column of their own; they
   ride the linked `tokens` row and therefore the token join table
   after switch-reads. Managed certificates that already resolve
   through a linked token do the same. Bootstrap tokens persist
   `contact_group_ids` JSONB on the same row (decision 1). Workspace
   contacts, webhook URL lists, and the JSONB group documents are
   unchanged.

### Schema implication

One migration (or a tight consecutive pair) must: add
`uq_tokens_workspace_id`; create both join tables and their indexes;
backfill from singular columns as specified in decision 1; create
`weekly_digest_recipient_log` with the unique key and claim columns in
decision 6. Digest claim logic must not ship against a table that lacks
that unique constraint, or two workers can both insert.

### Operational implication

The dual-write release does not change request or alert behavior:
operators still assign one group per asset. Join tables stay in sync
for the later switch. After switch-reads, old clients that only send
and read `contact_group_id` keep working through the compatibility
mirror (decision 3). New clients send `contact_group_ids`. Until the
follow-up that stops singular writes, operators can still see a single
id on GET; it is the lex-smallest assigned id, not a chosen primary.
Weekly digest delivery then depends on `weekly_digest_recipient_log`
claim rows. If that table is missing or the unique constraint is
absent, overlapping recipients can be double-messaged again. Generic
digest webhooks must keep the existing `contact_group` property and
add `contact_groups`; removing `contact_group` is a consumer break.

## Alternatives considered

- **Normalize `contact_groups` into real tables now** - rejected for
  this change: it forces a rewrite of the alert-settings API and UI
  that this record is not buying. JSONB groups plus application
  `assertContactGroupIds` remain. A later normalization can add FKs
  from the join tables without changing membership cardinality.
- **Join table authoritative immediately, without dual-write** -
  rejected: `Token.update`, import, agent registration, and bulk
  group-rewrite paths would race the cutover. A writer that still
  touched only the singular column would disappear from alert
  routing the moment readers switched. Dual-write then switch-reads
  then plural API is the order that keeps those paths honest.
- **Canonical singular id from `workspace_settings.contact_groups`
  JSON order** - rejected: that array order is mutable. Using it as
  canonical would require recomputing every asset's stored singular
  id on every reorder, including reorders that did not change
  membership. Lexicographically smallest assigned id is stable under
  reorder.
- **Per-group digest plus a recipient suppress log** - rejected: data
  loss. Alice in A `{X, Y}` and B `{Z}` would receive one group's
  assets and the suppress log would drop the other. Recipient-centric
  aggregation unions the sets, then sends once.
- **Explicit primary-group flag** - rejected: extra UX for a value
  that exists only so old clients have a single `contact_group_id`.
  Lex-smallest is a compatibility projection, not an operator
  preference.

## Consequences

- Old clients keep working via `contact_group_id` /
  `contactGroupId`. New field is `contact_group_ids` /
  `contactGroupIds` (including bootstrap minting).
- Stopping singular-column writes, then dropping
  `tokens.contact_group_id` and `certops_agents.contact_group_id`, is a
  follow-up ([#259](https://github.com/tokentimerch/tokentimer-core/issues/259)).
  This record's implementation dual-writes for its entire life.
- Digest templates that currently assume one group name must render
  the unioned asset set without splitting back into per-group sends.
- Tests must cover: workspace isolation of join rows; overlapping
  groups (same recipient, one threshold event, one message); shared
  recipients with non-overlapping asset sets (one digest containing
  the union, not a suppress-dropped subset); dual-write (join rows
  plus lex-smallest singular, including `[]` -> `NULL`); every request
  semantic in decision 4, including HTTP 400 when a present
  `contact_group_ids` / `contactGroupIds` is not an array of strings;
  atomic claim (two workers, one `RETURNING` owner); at-least-once
  email/webhook reclaim after an expired lease on `pending`; WhatsApp
  idempotency key shape without a group id; delivery re-deriving
  channels from current eligible groups (a queued email-only row that
  is reassigned to a WhatsApp group before send must send WhatsApp,
  not `NO_CONTACTS_DEFINED`).
- `assertContactGroupIds` and `replaceAssetContactGroups` are load
  bearing. A new import or integration `INSERT` that sets only
  `tokens.contact_group_id` is a bug against this record, not a
  private shortcut.
