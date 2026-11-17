"""Model choice and quota probing, through the real google-genai SDK.

A local HTTP server stands in for the Gemini API, so these tests exercise the
SDK's own request, paging and error handling without a key or network access.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tool_injection_eval import run

pytest.importorskip("google.genai")


def listed(name: str, *methods: str) -> dict:
    return {"name": f"models/{name}", "supportedGenerationMethods": list(methods)}


PAGES = [
    {
        "models": [
            listed("gemini-3.6-flash", "generateContent"),
            listed("gemini-3.9-flash-preview", "generateContent"),
            listed("text-embedding-005", "embedContent"),
        ],
        "nextPageToken": "page-2",
    },
    {
        "models": [
            listed("gemini-3.10-flash", "generateContent"),
            listed("gemini-3.8-flash-lite", "generateContent"),
            listed("gemini-3.12-flash", "countTokens"),
        ]
    },
]


def quota_error(quota_id: str) -> dict:
    return {
        "error": {
            "code": 429,
            "message": "You exceeded your current quota.",
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                    "violations": [{"quotaId": quota_id}],
                }
            ],
        }
    }


class FakeGemini(BaseHTTPRequestHandler):
    # model name -> (status, body) for generateContent
    replies: dict[str, tuple[int, dict]] = {}
    calls: list[str] = []

    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self.calls.append(f"GET {self.path}")
        self._send(200, PAGES[1] if "pageToken=page-2" in self.path else PAGES[0])

    def do_POST(self) -> None:
        self.calls.append(f"POST {self.path}")
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        model = self.path.split("/models/")[1].split(":")[0]
        ok = {"candidates": [{"content": {"role": "model", "parts": [{"text": "OK"}]}}]}
        self._send(*self.replies.get(model, (200, ok)))

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def fake_gemini(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[FakeGemini]]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGemini)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setattr(run, "PROBE_WAIT", 0.0)
    FakeGemini.replies, FakeGemini.calls = {}, []
    yield FakeGemini
    server.shutdown()


def test_picks_newest_stable_flash_then_flash_lite_across_pages(fake_gemini):
    assert run.gemini_models() == ["google/gemini-3.10-flash", "google/gemini-3.8-flash-lite"]
    assert sum(call.startswith("GET") for call in fake_gemini.calls) == 2


def test_probe_reports_ok(fake_gemini):
    assert run.probe("google/gemini-3.10-flash") == "ok"


def test_probe_reports_daily_quota(fake_gemini):
    error = quota_error("GenerateRequestsPerDayPerProjectPerModel-FreeTier")
    fake_gemini.replies["gemini-3.10-flash"] = (429, error)
    assert run.probe("google/gemini-3.10-flash") == "daily-quota"


def test_probe_retries_a_per_minute_limit(fake_gemini):
    error = quota_error("GenerateRequestsPerMinutePerProjectPerModel-FreeTier")
    fake_gemini.replies["gemini-3.10-flash"] = (429, error)
    assert run.probe("google/gemini-3.10-flash") == "rate-limited"
    posts = [call for call in fake_gemini.calls if call.startswith("POST")]
    assert len(posts) == run.PROBE_ATTEMPTS


def test_probe_reports_a_rejected_key(fake_gemini):
    error = {"error": {"code": 400, "message": "API key not valid.", "status": "INVALID_ARGUMENT"}}
    fake_gemini.replies["gemini-3.10-flash"] = (400, error)
    assert run.probe("google/gemini-3.10-flash").startswith("error 400")
