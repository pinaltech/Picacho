# Zero-access mail for Picacho

How to bring Pinal's zero-access storage (the Zero-Access Storage and Access Spec (draft),
"the spec") to Pinal Mail: Picacho Server (`Pinal Technologies/Picacho Mail/`,
crate `picacho-server`) and this app (the GPUI mail client).

**Status (2026-11-25):** not implemented in Picacho yet, by design: Pinal
Accounts, Pinal Photos and Mitten have it. Pinal Mail is listed in the
Privacy tab of accounts.pinal.tech as *coming soon* and stays readable by the
server until the work below ships. Everything Picacho needs from Pinal
Accounts already exists and is in production (see [What's already there](#whats-already-there)).

---

## 1. What changes for mail

| | Today | With zero access |
|---|---|---|
| Message bodies | AES-GCM with one server key (`storage.key`, `src/blob.rs`) | Per-message content key, sealed to the account's folder key (spec §4) |
| Index (envelope, subject, from, body text, bodystructure) | Plain columns in SQLite (`src/db.rs`, from `mime::summarize`) | Sealed with the message's content key; search runs on the client or in an Open-mode session |
| Calendars / contacts | Plain iCalendar / vCard | Same scheme, `calendar` and `contacts` folders (a later phase) |
| IMAP / SMTP submission / JMAP / DAV | Always on | Only in **Open mode**, with an app password (spec §6.2) |
| Pinal JWT (XOAUTH2) for IMAP | Reads everything | Account layer only: in Private mode it fetches ciphertext over the REST API |
| Incoming SMTP | Stored readable | Filtered (spam, Sieve) at arrival, then sealed and the plaintext dropped (spec §6.1) |

Pinal Mail's mode is per service: mail can be Open (for Thunderbird, Apple
Mail, phones) while Photos stays Private. **Private stays the default**, as
for every service; the Privacy tab explains that standard mail apps need
Open mode.

## 2. What's already there

Pinal Accounts (`PTech Login/`) runs the data layer for every service:

- `server/keys.js`: root-key wrappings, per-service keypairs (public halves
  in the clear, private halves wrapped by the root key, records signed by the
  account's identity key), service mode and version, signed device lists,
  key grants, app passwords, recovery, key transparency.
- `/api/internal/za/app-password` (service binding + `ZA_INTERNAL_SECRET`):
  takes an address, a service and the *auth half* of an app password, and
  returns that service's private keys wrapped by the other half. Picacho uses
  it exactly as `Pinal Photos/worker/src/dav.js` does for WebDAV.
- Key grants (spec §7.5): an app adds `zk_pub=<X25519 public key>` to its
  authorize request; the consent screen seals the keys for the services its
  scopes cover (`mail.*` → `mail`) to that key. The app fetches the grant
  from `GET /api/keys/grants/<id>`, `id = b64url(SHA-256("pinal-za/v1 grant-id:" ‖ pub))`.
  Grants and every service key in them are signed by the identity key.
- `ZA_SERVICES` lists services with zero-access storage. Adding `mail` makes
  sign-up create mail keys and lets the Privacy tab switch it.

The formats are fixed by `Pinal Technologies/zero-access/za.js`; Mitten's
`src/sources/pinal_za.rs` is a Rust port with interop tests against it
(`tests/fixtures/za-vectors.json`, made by `zero-access/test/make-vectors.js`).
**Start Picacho's Rust code from that file**: HPKE base mode
(DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM), `wrap`, chunked file
encryption (`PZA1`), canonical JSON, Ed25519 record checks.

## 3. Key hierarchy for mail

```
mail service key (X25519, per version)      ← Pinal Accounts
  └─ folder key per mailbox (X25519, per version)
       record: { v, service: "mail", folder: <mailbox id>, version, pub,
                 sealed: HPKE(service pub, folder priv,
                          info "pinal-za/v1 folder",
                          aad  "folder:mail:<mailbox id>:<version>"),
                 created, mac: HMAC(HKDF(service priv, "pinal-za/v1 folder-mac"), canonical(record − mac)) }
       └─ content key per message (32 random bytes)
            ek   = HPKE(folder pub, content key, "pinal-za/v1 content-key", "item:<message id>")
            blob = za file format, part "original"
            idx  = wrap(HKDF(content key, "pinal-za/v1 meta"), JSON index, "meta:<message id>")
```

- `<message id>` is a server-assigned random ID (not the IMAP UID, which can
  change with UIDVALIDITY). Store it beside the UID.
- Moving a message between mailboxes reseals only `ek` (open with the old
  folder key, seal to the new). In Private mode the client does that; in
  Open mode the server does it inside the session.
- Per-mailbox folder keys allow narrow grants later (`mail:folder:<id>`,
  spec §15 q2). A first version can use one folder key, `inbox`, for all
  mailboxes; keep the field so nothing has to migrate.

## 4. Picacho Server changes

### 4.1 Storage (`src/blob.rs`, `src/db.rs`, `src/server.rs`)

1. New table `za_message (message_id TEXT PK, mailbox_id, uid, fv INTEGER, ek BLOB, idx BLOB)`
   and `za_folder (account_id, folder, version, record TEXT)`. Keep the
   existing columns for accounts not migrated yet; once an account is
   zero-access, write empty strings into `envelope`, `bodystructure`, `body`,
   `subject`, `from_addr`, `meta`, `msgid`, `refs`.
2. `store_message` (`src/server.rs:31`) gets one more branch: if the account
   has a mail public key (fetched from Pinal Accounts and cached; see 4.4),
   run `mime::summarize` as today (arrival-time processing is allowed),
   serialize the summary to JSON, generate the content key, encrypt the blob
   and the index, seal the content key to the mailbox's folder key, store,
   and **zeroize** the raw message, summary and content key (`zeroize`
   crate). The server keeps the account's *public* keys only.
3. `storage.key` stays for accounts not yet migrated and for server-owned
   data (queue, reports). Zero-access blobs are already ciphertext; don't
   double-encrypt them.
4. Quotas use ciphertext sizes (a few bytes per 64 KiB more).

### 4.2 Incoming mail (`src/smtp/mod.rs`)

`deliver_local*` and `deliver_target` already end in `store_message`;
filtering (`src/filter`), Sieve (`src/sieve/deliver.rs`) and DMARC reporting
run before it, on the plaintext, at arrival. Two things change:

- Sieve scripts and Bayes data are the person's; in Private mode they would
  have to be client-side. A first version keeps them server-side (they're
  configuration, not mail) and says so in the Privacy tab.
- The Bayes filter must not keep tokens of messages (it learns from them).
  Store only counts keyed by HMAC(token) with a per-account key, or turn
  learning off for zero-access accounts.

### 4.3 Protocols in Private mode

IMAP, POP, SMTP submission, JMAP mail and CalDAV/CardDAV refuse to *read*
for zero-access accounts in Private mode (they can't: nothing to decrypt
with). Answer with the standard errors and a clear text, e.g. IMAP
`NO [AUTHORIZATIONFAILED] Pinal Mail is in Private mode. Use Picacho, or turn on Open mode at accounts.pinal.tech/account#privacy`.

The Pinal Mail REST API (`src/jmap/rest.rs`, `/v1/mail`) gets ciphertext
routes the client uses instead:

| Route | Returns |
|---|---|
| `GET /v1/mail/za/folders` | the folder records |
| `PUT /v1/mail/za/folders/:folder/:version` | a new folder record (create-only) |
| `GET /v1/mail/za/mailboxes/:id/messages?since=<modseq>` | `{ id, uid, fv, ek, idx, size, flags, modseq }` pages |
| `GET /v1/mail/za/messages/:id/blob` | the encrypted message (ranges) |
| `POST /v1/mail/za/messages` | append: encrypted blob + `ek` + `idx` (drafts, Sent) |
| `POST /v1/mail/za/messages/:id/key` | reseal `ek` (move, rotation) |
| `POST /v1/mail/za/send` | submit a message for delivery (see 4.6) |

Flags, mailbox membership and MODSEQ stay server-side and readable (they
are metadata, spec §2).

### 4.4 Open mode (`src/auth.rs`, `src/imap/mod.rs`, `src/smtp/mod.rs`, `src/jmap`, `src/dav`)

App passwords (spec §6.2) replace the Pinal JWT for standard clients:

1. On `LOGIN` / `AUTHENTICATE PLAIN` (IMAP), `AUTH PLAIN/LOGIN` (submission),
   HTTP Basic (JMAP, DAV): split the password exactly as `za.splitSecret`:
   `auth = HKDF(P, "pinal-za/v1 app-pw-auth")`, `wrap = HKDF(P, "pinal-za/v1 app-pw-wrap")`.
2. POST `{ service: "mail", username, auth: b64url(auth) }` to Pinal
   Accounts' `/api/internal/za/app-password` (header `X-ZA-Internal`). It
   answers `{ userId, wrapped: { version: wrap }, publicKeys }` or 401. It
   checks the mode itself: a 401 is also what Private mode looks like.
3. Unwrap each version: `unwrap(wrap, wrapped[v], "pinal-za/v1 app-pw:mail:<v>")`.
   Open the folder records (check the MAC first) into a **session key
   ring** that lives in the connection's task, in `zeroize`-on-drop types.
4. Decrypt the index of the selected mailbox on `SELECT` into the session's
   in-memory index; IMAP SEARCH, SORT, THREAD, FETCH ENVELOPE /
   BODYSTRUCTURE work on that. JMAP and DAV do the same per request (cache
   per app password for a few minutes, like `dav.js`, and **re-check the app
   password with Pinal Accounts on every new connection and at least every
   minute**, so deleting it or leaving Open mode cuts the client off).
5. On logout, connection close or idle timeout, drop the key ring and index.
6. `IDLE` keeps keys in memory for as long as it lasts: this is the
   accepted cost of Open mode (spec §12.2) and the Privacy tab says so.

Rate-limit app-password failures with the existing login limiter
(5 / 15 min per IP); Pinal Accounts limits per account too.

### 4.5 Mode switches (spec §9)

Pinal Accounts owns the mode. Picacho learns it from the app-password
answer (Open) and from a new internal route it can poll or be told about:

- **Private → Open:** nothing to do server-side; app passwords start working.
- **Open → Private:** Pinal Accounts deletes the app passwords and makes a
  new mail key version. Picacho must end live sessions for that account at
  once: add `POST /api/v1/za/sessions/:account/revoke` (admin token, called
  by Pinal Accounts' `POST /api/keys/services/mail`) that closes IMAP/JMAP
  connections and drops cached keys. New mail is then sealed to the new
  folder keys (created by the client on its next sync); the client reseals
  old `ek`s in the background and retires old versions, as Pinal Photos'
  `web/vault.js` does.

### 4.6 Sending

SMTP to other servers needs the plaintext, so:

- **Private mode:** the client builds the MIME message, encrypts a copy for
  Sent (`POST /v1/mail/za/messages`), and submits the plaintext over TLS to
  `POST /v1/mail/za/send`. The server queues it (`src/queue.rs`) for
  delivery and deletes it once delivered. That plaintext is in transit, as
  for incoming mail (spec §2). DKIM signing stays server-side.
- **Open mode:** SMTP submission works as today; the Sent copy is sealed on
  arrival like any other message.
- End-to-end (PGP / S/MIME) is out of scope here.

### 4.7 Migration of existing mailboxes

A mailbox already on the server is readable by it, so migration is the one
time the server encrypts old mail: for each message, decrypt with
`storage.key`, seal as in 4.1, delete the old blob and clear the index
columns. Run it as a background job per account when the account's mail key
appears (first sign-in after `mail` is added to `ZA_SERVICES`). Then tell
the person, in the Privacy tab, that the copies Pinal held before that date
were readable while they existed.

### 4.8 Tests

- Keep the baselines in `Picacho Mail/scripts/` (imaptest 0/460 + 0/266,
  litmus 104/104, CalDAVTester core subset) **in Open mode** with an app
  password: protocol behaviour must not change.
- New tests: a zero-access account in Private mode refuses IMAP reads; its
  SQLite rows and blob files contain no plaintext (grep for a marker phrase
  sent in a test message, as `zero-access/verify/` does for Photos); Open
  mode reads, then fails right after the app password is deleted.

## 5. Picacho app changes (this repository)

The app signs in to Pinal as a native developer app (`Service::Pinal`).

1. **Key grant.** Add `zk_pub` to the authorize request in the Pinal sign-in
   (generate an X25519 key per sign-in, as Mitten's `SignIn::start` does) and
   fetch the grant after the token exchange. Copy
   `GPUI Photos/src/sources/pinal_za.rs` into a shared crate (or vendor it)
   rather than reimplementing. Show the confirmation code during sign-in.
2. **Keys at rest.** Keep the mail service keys in the system keyring next
   to the refresh token. Never write them to the cache database.
3. **Private-mode sync.** When the grant's mail mode is `private`, use the
   `/v1/mail/za` routes instead of IMAP: fetch pages of `{ ek, idx }`, open
   them into the local store (decrypted index in the app's encrypted local
   database), fetch and decrypt blobs on demand. Search runs locally.
4. **Writes.** Flags and moves use the REST API (moves reseal `ek`); drafts
   and Sent copies are encrypted before upload; sending uses `/za/send`.
5. **Open mode.** Keep today's IMAP/SMTP path, but sign in with an app
   password the user pastes (or offer "Use Private mode" instead).
6. **Rotation.** On "unknown folder version" or a newer service version in
   the grant answer, get a fresh grant (re-run the consent flow with
   `zk_pub`), then reseal old `ek`s in the background and call
   `POST https://accounts.pinal.tech/api/keys/services/mail/retire`.
7. **Settings.** Show the mail mode with a link to the Privacy tab; don't
   switch modes in the app (the root key lives in the browser).

## 6. Order of work

1. Port `pinal_za.rs` into a crate both Picacho Server and the app use.
2. Server: `za_*` tables, sealing in `store_message`, ciphertext REST routes,
   Private-mode refusals. Ship behind `ZA_SERVICES` not containing `mail`.
3. App: grant + Private-mode sync. Test against a staging account.
4. Server: Open mode (app passwords in IMAP/SMTP/JMAP/DAV, session key rings,
   revocation route). Rerun the three conformance suites.
5. Migration job; add `mail` to `ZA_SERVICES` on Pinal Accounts; deploy the
   server on the VPS (`ubuntu@40.160.151.245`, `~/picacho-src`, systemd unit
   `picacho`); update the Privacy tab copy.
6. Calendars and contacts the same way (`calendar`, `contacts` folders).
