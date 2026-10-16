from app.services.training import SCENARIOS, grade


def test_catalog_is_public_and_does_not_reveal_answers(client):
    response = client.get("/api/v1/training/scenarios")
    assert response.status_code == 200
    catalog = response.json()
    assert catalog["total"] == 10
    for scenario in catalog["items"]:
        assert "indicators" not in scenario
        assert "safe_elements" not in scenario
        assert "lesson" not in scenario
        detail = client.get(f"/api/v1/training/scenarios/{scenario['id']}")
        assert detail.status_code == 200
        body = detail.json()
        assert body["elements"]
        assert "indicators" not in body
        assert "correct_indicator_ids" not in body
        assert "safe_elements" not in body
        assert "lesson" not in body
        assert all("correct" not in element for element in body["elements"])


def test_catalog_filters_and_missing_scenario(client):
    response = client.get("/api/v1/training/scenarios?difficulty=easy&channel=sms")
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["id"] == "delivery-fee"
    assert client.get("/api/v1/training/scenarios/unknown").status_code == 404
    assert client.get("/api/v1/training/scenarios?difficulty=impossible").status_code == 422


def test_attempts_and_progress_require_authentication(client):
    assert client.post("/api/v1/training/attempts", json={"scenario_id": "upi-refund"}).status_code == 401
    assert client.get("/api/v1/training/progress").status_code == 401
    assert client.get("/api/v1/training/attempts/unknown").status_code == 401


def test_submission_is_final_and_xp_is_awarded_once(client, auth_headers):
    response = client.post(
        "/api/v1/training/attempts", json={"scenario_id": "upi-refund"}, headers=auth_headers
    )
    assert response.status_code == 201
    attempt = response.json()
    assert attempt["status"] == "in_progress"
    assert attempt["result"] is None

    repeat = client.post(
        "/api/v1/training/attempts", json={"scenario_id": "upi-refund"}, headers=auth_headers
    )
    assert repeat.status_code == 200
    assert repeat.json()["id"] == attempt["id"]

    path = f"/api/v1/training/attempts/{attempt['id']}/submit"
    submission = {"selected_indicator_ids": ["pin", "collect"]}
    submitted = client.post(path, json=submission, headers=auth_headers)
    assert submitted.status_code == 200
    result = submitted.json()["result"]
    assert result["score"] == 100
    assert result["xp_earned"] == 40
    assert result["missed_count"] == 0
    assert result["false_positive_count"] == 0
    assert result["lesson"]
    assert len(result["indicators"]) == 2

    repeated = client.post(path, json={"selected_indicator_ids": ["collect", "pin"]}, headers=auth_headers)
    assert repeated.status_code == 200
    assert repeated.json() == submitted.json()
    assert client.post(path, json={"selected_indicator_ids": []}, headers=auth_headers).status_code == 409

    progress = client.get("/api/v1/training/progress", headers=auth_headers).json()
    assert progress["total_xp"] == 40
    assert progress["completed_scenarios"] == 1
    assert progress["average_accuracy"] == 100
    assert progress["perfect_scenarios"] == 1


def test_bad_selections_do_not_consume_attempt(client, auth_headers):
    attempt = client.post(
        "/api/v1/training/attempts", json={"scenario_id": "bank-account-review"}, headers=auth_headers
    ).json()
    path = f"/api/v1/training/attempts/{attempt['id']}/submit"
    assert (
        client.post(path, json={"selected_indicator_ids": ["unknown"]}, headers=auth_headers).status_code
        == 422
    )
    assert (
        client.post(
            path, json={"selected_indicator_ids": ["sender", "sender"]}, headers=auth_headers
        ).status_code
        == 422
    )
    assert client.post(path, json={"selected_indicator_ids": [123]}, headers=auth_headers).status_code == 422
    current = client.get(f"/api/v1/training/attempts/{attempt['id']}", headers=auth_headers).json()
    assert current["status"] == "in_progress"
    assert current["result"] is None
    assert client.post(path, json={"selected_indicator_ids": []}, headers=auth_headers).status_code == 200


def test_safe_control_accepts_no_selection(client, auth_headers):
    attempt = client.post(
        "/api/v1/training/attempts", json={"scenario_id": "order-receipt"}, headers=auth_headers
    ).json()
    response = client.post(
        f"/api/v1/training/attempts/{attempt['id']}/submit",
        json={"selected_indicator_ids": []},
        headers=auth_headers,
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["score"] == 100
    assert result["xp_earned"] == 60
    assert result["correct_indicator_ids"] == []
    assert result["indicators"] == []


def test_false_positives_lower_the_score():
    scenario = SCENARIOS["upi-refund"]
    perfect = grade(scenario, ["collect", "pin"])
    noisy = grade(scenario, ["collect", "pin", "greeting"])
    missed = grade(scenario, ["collect"])
    assert perfect["score"] == 100
    assert 0 < noisy["score"] < perfect["score"]
    assert noisy["false_positive_count"] == 1
    assert noisy["false_positives"][0]["explanation"]
    assert missed["score"] == 50
    assert missed["missed_count"] == 1
    assert grade(SCENARIOS["order-receipt"], ["from"])["score"] == 0


def test_unknown_attempt_is_not_exposed(client, auth_headers):
    assert client.get("/api/v1/training/attempts/not-owned", headers=auth_headers).status_code == 404
    assert (
        client.post(
            "/api/v1/training/attempts/not-owned/submit",
            json={"selected_indicator_ids": []},
            headers=auth_headers,
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/api/v1/training/attempts", json={"scenario_id": "unknown"}, headers=auth_headers
        ).status_code
        == 404
    )


def test_attempts_are_private_to_the_owner(client, auth_headers):
    attempt = client.post(
        "/api/v1/training/attempts", json={"scenario_id": "upi-refund"}, headers=auth_headers
    ).json()
    second = client.post(
        "/api/v1/auth/register",
        json={
            "email": "second-learner@example.com",
            "display_name": "Second learner",
            "password": "AnotherSecurePass42!",
        },
    )
    assert second.status_code == 201
    other_headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
    path = f"/api/v1/training/attempts/{attempt['id']}"
    assert client.get(path, headers=other_headers).status_code == 404
    assert (
        client.post(f"{path}/submit", json={"selected_indicator_ids": []}, headers=other_headers).status_code
        == 404
    )
    assert client.get("/api/v1/training/progress", headers=other_headers).json()["completed_scenarios"] == 0
