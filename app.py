from flask import Flask, request, jsonify

app = Flask(__name__)

WORKSPACE = "prod-doom1t"

REQUIRED_LABELS = {
    "owner": "student-rwd6g",
    "environment": "production",
    "cost_center": "cc-pupw",
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
DANGEROUS_DELETE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


def reject(reason):
    return jsonify({
        "decision": "reject",
        "reason": reason
    }), 200


def approve():
    return jsonify({
        "decision": "approve",
        "reason": "APPROVE"
    }), 200


def is_valid_plan(data):
    """Rule 1: Validate the request and nested object types."""

    if not isinstance(data, dict):
        return False

    # Top-level fields
    if not isinstance(data.get("environment"), str):
        return False

    if not isinstance(data.get("state"), dict):
        return False

    if not isinstance(data.get("providerVersion"), str):
        return False

    if not isinstance(data.get("destroyApproved"), bool):
        return False

    if not isinstance(data.get("resource"), dict):
        return False

    state = data["state"]

    if not isinstance(state.get("backend"), str):
        return False

    if not isinstance(state.get("locked"), bool):
        return False

    resource = data["resource"]

    if not isinstance(resource.get("address"), str):
        return False

    if not isinstance(resource.get("type"), str):
        return False

    if not isinstance(resource.get("action"), str):
        return False

    if resource.get("action") not in {"create", "update", "delete"}:
        return False

    if not isinstance(resource.get("labels"), dict):
        return False

    secret = resource.get("secret")

    if secret is not None and not isinstance(secret, str):
        return False

    if not isinstance(resource.get("forceDestroy"), bool):
        return False

    return True


@app.post("/terraform/plan")
def terraform_plan():
    # Parse JSON safely.
    data = request.get_json(silent=True)

    # Rule 1: types / structure
    if not is_valid_plan(data):
        return reject("INVALID_PLAN")

    # Rule 2: environment
    if data["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # Rule 3: remote state + locking
    state = data["state"]

    if state["backend"] not in ALLOWED_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # Rule 4: provider pinning
    provider_version = data["providerVersion"]

    allowed_provider_versions = {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }

    if provider_version not in allowed_provider_versions:
        return reject("UNPINNED_PROVIDER")

    # Rule 5: required labels
    labels = data["resource"]["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return reject("MISSING_LABELS")

    # Rule 6: secret must be null or secret://...
    secret = data["resource"]["secret"]

    if secret is not None:
        if not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

        # "secret://" by itself is not a non-empty reference.
        if len(secret) <= len("secret://"):
            return reject("PLAINTEXT_SECRET")

    # Rule 7: dangerous stateful deletes need approval
    resource = data["resource"]

    if (
        resource["action"] == "delete"
        and resource["type"] in DANGEROUS_DELETE_TYPES
        and data["destroyApproved"] is not True
    ):
        return reject("DELETE_NOT_APPROVED")

    # Rule 8: production storage buckets cannot force destroy
    if (
        data["environment"] == "prod-doom1t"
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    # Everything passed.
    return approve()


@app.get("/")
def health_check():
    return jsonify({
        "status": "ok"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000
    )
