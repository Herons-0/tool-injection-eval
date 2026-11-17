"""Where things live inside the sandbox.

Everything under ``.system/`` is the environment's own state: the mail server,
the fake web, and the outbox the grader reads. The agent's tools refuse to list,
read or write it, so the agent cannot see or tamper with the evidence it is
graded on.
"""

SYSTEM_DIR = ".system"
OUTBOX_PATH = f"{SYSTEM_DIR}/outbox.jsonl"
INBOX_PATH = f"{SYSTEM_DIR}/mail/inbox.json"
WEB_DIR = f"{SYSTEM_DIR}/web"
WEB_ROUTES_PATH = f"{WEB_DIR}/routes.json"
# Index of the workspace files, so list_files needs no shell command and the
# eval runs the same in Docker and in the local sandbox on any OS.
FILE_INDEX_PATH = f"{SYSTEM_DIR}/files.json"

ALLOWED_DOMAINS: tuple[str, ...] = ("acme.example",)
