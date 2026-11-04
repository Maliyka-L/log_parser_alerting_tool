import datetime

from src import main

#tests whether discord alerting exits safely when no webhook URL is configured.
def test_send_alert_no_webhook(monkeypatch):
    monkeypatch.setattr(main, "WEBHOOK_URL", "")

    alerts = [{
        "ip": "1.1.1.1",
        "time": datetime.datetime.now(),
        "reason": "Test",
        "type": "test",
        "severity": "low"
    }]

    main.send_alert(alerts)


#tests whether every alert is included in the Discord message (not just the last one).
def test_send_alert_includes_all_alerts(monkeypatch):
    sent = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

    def fake_post(url, json=None, timeout=None):
        sent["payload"] = json
        return FakeResponse()

    monkeypatch.setattr(main, "WEBHOOK_URL", "https://example.invalid/webhook")
    monkeypatch.setattr(main.requests, "post", fake_post)

    alerts = [
        {"ip": "1.1.1.1", "time": datetime.datetime.now(), "reason": "A", "type": "bruteforce", "severity": "high"},
        {"ip": "2.2.2.2", "time": datetime.datetime.now(), "reason": "B", "type": "admin_access", "severity": "medium"},
        {"ip": "3.3.3.3", "time": datetime.datetime.now(), "reason": "C", "type": "after_hours", "severity": "low"},
    ]

    main.send_alert(alerts)

    assert len(sent["payload"]["embeds"][0]["fields"]) == 3
