# MIMF CLI Reference (v1.0.0)

Generated: 2026-02-12T20:11:57Z

## mimf --help

usage: mimf [-h]
            {list-plugins,inspect-file,normalize-file,show-normalized,export-bundle,show-bundle,verify-bundle,keygen,append-custody,transfer-custody,accept-transfer,timeline,bundle-diff,db-init,db-list-contexts,db-show-context,serve,client,demo}
            ...

MIMF CLI

positional arguments:
  {list-plugins,inspect-file,normalize-file,show-normalized,export-bundle,show-bundle,verify-bundle,keygen,append-custody,transfer-custody,accept-transfer,timeline,bundle-diff,db-init,db-list-contexts,db-show-context,serve,client,demo}
    list-plugins        List built-in plugins
    inspect-file        Inspect a local file
    normalize-file      Inspect a file and attach normalized metadata
    show-normalized     Inspect a file and print normalized output (no
                        mutation)
    export-bundle       Create a tamper-evident forensic export bundle
    show-bundle         Show a human-friendly summary of a bundle
    verify-bundle       Verify a forensic bundle directory
    keygen              Generate an Ed25519 keypair for signing bundles
    append-custody      Append a chain-of-custody event to an existing bundle
    transfer-custody    Create a sender-signed transfer receipt
    accept-transfer     Accept a transfer receipt (receiver-signed)
    timeline            Show a chronological timeline for a bundle
    bundle-diff         Diff two bundle directories
    db-init             Initialize a SQLite runtime store
    db-list-contexts    List contexts stored in a SQLite runtime store
    db-show-context     Show a stored context (objects + events)
    serve               Run the MIMF FastAPI server
    client              MIMF API client (talk to a running server)
    demo                End-to-end demo against a running API

options:
  -h, --help            show this help message and exit


## mimf list-plugins --help

usage: mimf list-plugins [-h]

options:
  -h, --help  show this help message and exit


## mimf inspect-file --help

usage: mimf inspect-file [-h] [--object-id OBJECT_ID]
                         [--context-id CONTEXT_ID] [--actor-id ACTOR_ID]
                         [--sandbox]
                         path

positional arguments:
  path                  Path to file

options:
  -h, --help            show this help message and exit
  --object-id OBJECT_ID
                        Override RuntimeObject.object_id
  --context-id CONTEXT_ID
                        Override RuntimeContext.context_id
  --actor-id ACTOR_ID   Optional actor id
  --sandbox             Run inspector in a subprocess sandbox


## mimf normalize-file --help

usage: mimf normalize-file [-h] [--object-id OBJECT_ID]
                           [--context-id CONTEXT_ID] [--actor-id ACTOR_ID]
                           [--plan-id PLAN_ID] [--apply] [--sandbox]
                           path

positional arguments:
  path                  Path to file

options:
  -h, --help            show this help message and exit
  --object-id OBJECT_ID
                        Override RuntimeObject.object_id
  --context-id CONTEXT_ID
                        Override RuntimeContext.context_id
  --actor-id ACTOR_ID   Optional actor id
  --plan-id PLAN_ID     Override MutationPlan.plan_id
  --apply               Apply mutation (default is dry-run)
  --sandbox             Run inspector in a subprocess sandbox


## mimf show-normalized --help

usage: mimf show-normalized [-h] [--object-id OBJECT_ID] [--sandbox]
                            [--policy-pack POLICY_PACK]
                            [--boundary-id BOUNDARY_ID]
                            [--boundary-capability BOUNDARY_CAPABILITY]
                            [--actor-capability ACTOR_CAPABILITY] [--strict]
                            path

positional arguments:
  path                  Path to file

options:
  -h, --help            show this help message and exit
  --object-id OBJECT_ID
                        Override RuntimeObject.object_id
  --sandbox             Run inspector in a subprocess sandbox
  --policy-pack POLICY_PACK
                        Policy pack name/path (overrides
                        boundary/actor/strict)
  --boundary-id BOUNDARY_ID
                        Security boundary id for export
  --boundary-capability BOUNDARY_CAPABILITY
                        Boundary allowed capability (repeatable)
  --actor-capability ACTOR_CAPABILITY
                        Actor capability (repeatable)
  --strict              Deny export instead of redacting when capabilities are
                        missing


## mimf export-bundle --help

usage: mimf export-bundle [-h] [--object-id OBJECT_ID] [--sandbox]
                          [--context-id CONTEXT_ID] [--actor-id ACTOR_ID]
                          [--plan-id PLAN_ID] [--policy-pack POLICY_PACK]
                          [--out OUT] [--zip] [--include-original]
                          [--include-absolute-path] [--apply]
                          [--boundary-id BOUNDARY_ID]
                          [--boundary-capability BOUNDARY_CAPABILITY]
                          [--actor-capability ACTOR_CAPABILITY] [--strict]
                          [--pretty] [--events EVENTS] [--sign] [--key KEY]
                          [--signer-id SIGNER_ID] [--embed-pubkey] [--db DB]
                          [--persist] [--overwrite-context]
                          path

positional arguments:
  path                  Path to file

options:
  -h, --help            show this help message and exit
  --object-id OBJECT_ID
                        Override RuntimeObject.object_id
  --sandbox             Run inspector in a subprocess sandbox
  --context-id CONTEXT_ID
                        Override RuntimeContext.context_id
  --actor-id ACTOR_ID   Optional actor id
  --plan-id PLAN_ID     Override normalization MutationPlan.plan_id
  --policy-pack POLICY_PACK
                        Policy pack name/path (overrides
                        boundary/actor/strict)
  --out OUT             Output directory (created if missing)
  --zip                 Also create a .zip of the bundle directory
  --include-original    Copy the original file into the bundle
  --include-absolute-path
                        Record absolute path in manifest
  --apply               Apply normalization mutation (default is dry-run)
  --boundary-id BOUNDARY_ID
                        Security boundary id used for normalized export
  --boundary-capability BOUNDARY_CAPABILITY
                        Boundary allowed capability for export (repeatable)
  --actor-capability ACTOR_CAPABILITY
                        Actor capability for export (repeatable)
  --strict              Deny export instead of redacting when capabilities are
                        missing
  --pretty              Print a human-friendly report instead of JSON
  --events EVENTS       When using --pretty, include the first N events
                        (default: 0)
  --sign                Create a detached Ed25519 signature for the bundle
                        (authenticity)
  --key KEY             Path to Ed25519 PRIVATE key PEM (required with --sign)
  --signer-id SIGNER_ID
                        Optional signer id (e.g., operator or system id)
  --embed-pubkey        Embed the derived public key inside the bundle
                        (convenient but not trusted)
  --db DB               SQLite DB path to persist RuntimeContext (optional)
  --persist             Persist the RuntimeContext into --db after export
  --overwrite-context   Overwrite existing context row when persisting


## mimf show-bundle --help

usage: mimf show-bundle [-h] [--verify] [--pubkey PUBKEY]
                        [--custody-pubkey CUSTODY_PUBKEY]
                        [--sender-pubkey SENDER_PUBKEY]
                        [--receiver-pubkey RECEIVER_PUBKEY] [--events EVENTS]
                        [--json]
                        bundle_dir

positional arguments:
  bundle_dir            Path to bundle directory

options:
  -h, --help            show this help message and exit
  --verify              Also verify bundle integrity
  --pubkey PUBKEY       Path to Ed25519 PUBLIC key PEM (enables signature
                        verification)
  --custody-pubkey CUSTODY_PUBKEY
                        Path to Ed25519 PUBLIC key PEM for custody addendum
                        (defaults to --pubkey)
  --sender-pubkey SENDER_PUBKEY
                        Path to sender Ed25519 PUBLIC key PEM (verifies
                        transfer receipts)
  --receiver-pubkey RECEIVER_PUBKEY
                        Path to receiver Ed25519 PUBLIC key PEM (verifies
                        transfer receipts)
  --events EVENTS       Include the first N events (default: 0)
  --json                Print raw JSON (manifest + file_summary)


## mimf verify-bundle --help

usage: mimf verify-bundle [-h] [--pubkey PUBKEY]
                          [--custody-pubkey CUSTODY_PUBKEY]
                          [--sender-pubkey SENDER_PUBKEY]
                          [--receiver-pubkey RECEIVER_PUBKEY]
                          bundle_dir

positional arguments:
  bundle_dir            Path to bundle directory

options:
  -h, --help            show this help message and exit
  --pubkey PUBKEY       Path to Ed25519 PUBLIC key PEM (enables signature
                        verification)
  --custody-pubkey CUSTODY_PUBKEY
                        Path to Ed25519 PUBLIC key PEM for custody addendum
                        (defaults to --pubkey)
  --sender-pubkey SENDER_PUBKEY
                        Path to sender Ed25519 PUBLIC key PEM (verifies
                        transfer receipts)
  --receiver-pubkey RECEIVER_PUBKEY
                        Path to receiver Ed25519 PUBLIC key PEM (verifies
                        transfer receipts)


## mimf keygen --help

usage: mimf keygen [-h] [--prefix PREFIX] out_dir

positional arguments:
  out_dir          Directory to write keys into

options:
  -h, --help       show this help message and exit
  --prefix PREFIX  Filename prefix for the generated key files


## mimf append-custody --help

usage: mimf append-custody [-h] [--actor-id ACTOR_ID] [--note NOTE]
                           [--signer-id SIGNER_ID] [--key KEY]
                           [--embed-pubkey]
                           bundle_dir action

positional arguments:
  bundle_dir            Path to bundle directory
  action                Custody action (e.g., CREATED, TRANSFERRED, ACCESSED)

options:
  -h, --help            show this help message and exit
  --actor-id ACTOR_ID   Optional actor id
  --note NOTE           Optional free-text note
  --signer-id SIGNER_ID
                        Optional signer id
  --key KEY             Path to Ed25519 PRIVATE key PEM (signs custody
                        addendum)
  --embed-pubkey        Embed derived public key in custody/public_key.pem
                        (convenient but not trusted)


## mimf transfer-custody --help

usage: mimf transfer-custody [-h] [--note NOTE] [--signer-id SIGNER_ID]
                             [--key KEY] [--embed-pubkey]
                             bundle_dir from_actor_id to_actor_id

positional arguments:
  bundle_dir            Path to bundle directory
  from_actor_id         Sender/owner id
  to_actor_id           Receiver id

options:
  -h, --help            show this help message and exit
  --note NOTE           Optional free-text note
  --signer-id SIGNER_ID
                        Optional signer id
  --key KEY             Path to Ed25519 PRIVATE key PEM (sender)
  --embed-pubkey        Embed sender public key inside the receipt (convenient
                        but not trusted)


## mimf accept-transfer --help

usage: mimf accept-transfer [-h] [--receipt RECEIPT] [--actor-id ACTOR_ID]
                            [--signer-id SIGNER_ID] [--key KEY]
                            [--embed-pubkey]
                            bundle_dir

positional arguments:
  bundle_dir            Path to bundle directory

options:
  -h, --help            show this help message and exit
  --receipt RECEIPT     Receipt relpath (default: latest pending receipt)
  --actor-id ACTOR_ID   Receiver actor id
  --signer-id SIGNER_ID
                        Optional signer id
  --key KEY             Path to Ed25519 PRIVATE key PEM (receiver)
  --embed-pubkey        Embed receiver public key inside the receipt
                        (convenient but not trusted)


## mimf timeline --help

usage: mimf timeline [-h] [--events EVENTS] [--custody CUSTODY]
                     [--limit LIMIT] [--json]
                     bundle_dir

positional arguments:
  bundle_dir         Path to bundle directory

options:
  -h, --help         show this help message and exit
  --events EVENTS    Max events to read from events.jsonl
  --custody CUSTODY  Max custody artifacts to read
  --limit LIMIT      Limit timeline rows (0=all)
  --json             Print JSON


## mimf bundle-diff --help

usage: mimf bundle-diff [-h] [--limit LIMIT] [--json] bundle_a bundle_b

positional arguments:
  bundle_a       Path to bundle A
  bundle_b       Path to bundle B

options:
  -h, --help     show this help message and exit
  --limit LIMIT  Max diff entries
  --json         Print JSON diff


## mimf db-init --help

usage: mimf db-init [-h] --db DB

options:
  -h, --help  show this help message and exit
  --db DB     Path to SQLite DB file


## mimf db-list-contexts --help

usage: mimf db-list-contexts [-h] --db DB [--limit LIMIT]

options:
  -h, --help     show this help message and exit
  --db DB        Path to SQLite DB file
  --limit LIMIT  Max contexts to show


## mimf db-show-context --help

usage: mimf db-show-context [-h] --db DB [--events EVENTS] context_id

positional arguments:
  context_id       Context ID

options:
  -h, --help       show this help message and exit
  --db DB          Path to SQLite DB file
  --events EVENTS  Number of events to include


## mimf serve --help

usage: mimf serve [-h] [--host HOST] [--port PORT] [--db DB]
                  [--log-level LOG_LEVEL]

options:
  -h, --help            show this help message and exit
  --host HOST           Bind host (default: 127.0.0.1)
  --port PORT           Bind port (default: 8080)
  --db DB               Optional SQLite DB path for persistence endpoints
  --log-level LOG_LEVEL
                        Uvicorn log level


## mimf client --help

usage: mimf client [-h] [--url URL] [--api-key API_KEY]
                   [--max-upload-bytes MAX_UPLOAD_BYTES]
                   {health,inspect,normalize,export-bundle,verify-bundle} ...

positional arguments:
  {health,inspect,normalize,export-bundle,verify-bundle}
    health              Check server health
    inspect             Upload a file for inspection
    normalize           Upload a file for normalization (policy-controlled)
    export-bundle       Export a forensic bundle zip (from API)
    verify-bundle       Verify a bundle zip via API

options:
  -h, --help            show this help message and exit
  --url URL             Base API URL
  --api-key API_KEY     API key (X-MIMF-API-Key)
  --max-upload-bytes MAX_UPLOAD_BYTES
                        Client-side upload cap


## mimf demo --help

usage: mimf demo [-h] [--url URL] [--api-key API_KEY] [--labels LABELS]
                 [--out OUT] [--include-original] [--persist]
                 [--boundary-id BOUNDARY_ID] [--boundary-caps BOUNDARY_CAPS]
                 [--strict] [--max-upload-bytes MAX_UPLOAD_BYTES]
                 [--public-key PUBLIC_KEY]
                 [--custody-public-key CUSTODY_PUBLIC_KEY]
                 [--sender-public-key SENDER_PUBLIC_KEY]
                 [--receiver-public-key RECEIVER_PUBLIC_KEY]
                 file

positional arguments:
  file                  Path to local file

options:
  -h, --help            show this help message and exit
  --url URL             Base API URL
  --api-key API_KEY     API key
  --labels LABELS       Comma-separated labels
  --out OUT             Output bundle zip filename
  --include-original    Include original bytes in bundle
  --persist             Persist context in server DB (requires runtime:write)
  --boundary-id BOUNDARY_ID
                        Boundary id
  --boundary-caps BOUNDARY_CAPS
                        Comma-separated boundary caps (hint)
  --strict              Deny instead of redact
  --max-upload-bytes MAX_UPLOAD_BYTES
                        Client-side upload cap
  --public-key PUBLIC_KEY
                        Bundle signature pubkey (optional)
  --custody-public-key CUSTODY_PUBLIC_KEY
                        Custody pubkey (optional)
  --sender-public-key SENDER_PUBLIC_KEY
                        Sender receipt pubkey (optional)
  --receiver-public-key RECEIVER_PUBLIC_KEY
                        Receiver receipt pubkey (optional)

