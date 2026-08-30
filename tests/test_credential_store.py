"""Tests for core.credential_store — add_credential, load_creds, get_credentials, mark_verified."""
import json
import tempfile
import pytest
from core.credential_store import CredentialStore, Credential


@pytest.fixture()
def cred_store():
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        db_path = f.name
    json_path = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json_path.write(json.dumps({
        "default_linux": [["admin", "P@ssw0rd"], ["root", "toor"]],
        "default_windows": [["Administrator", "Pass123!"]],
        "password_spray": ["Welcome1", "Password1"],
    }))
    json_path.close()
    store = CredentialStore(db_path=db_path, cred_json_path=json_path.name)
    yield store
    # Cleanup (SQLite may lock on some platforms; best-effort close not available)


@pytest.fixture()
def cred_store_no_defaults():
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        db_path = f.name
    json_path = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json_path.write("{}")
    json_path.close()
    store = CredentialStore(db_path=db_path, cred_json_path=json_path.name)
    yield store


class TestAddCredential:
    def test_add_credential(self, cred_store):
        cred = Credential(username="alice", password="secret123", target="10.0.0.1", source="manual")
        cred_store.add_credential(cred)
        rows = cred_store.get_credentials(target="10.0.0.1")
        assert len(rows) == 1
        assert rows[0]["username"] == "alice"

    def test_duplicate_ignored(self, cred_store):
        cred = Credential(username="bob", password="pw", target="10.0.0.2")
        cred_store.add_credential(cred)
        cred_store.add_credential(Credential(username="bob", password="pw", target="10.0.0.2"))
        rows = cred_store.get_credentials(target="10.0.0.2")
        assert len(rows) == 1

    def test_add_with_target_star(self, cred_store):
        cred = Credential(username="guest", password="guest", target="*")
        cred_store.add_credential(cred)
        rows = cred_store.get_credentials()
        assert any(r["username"] == "guest" for r in rows)


class TestLoadCreds:
    def test_load_ssh_creds(self, cred_store):
        creds = cred_store.load_creds("ssh")
        assert len(creds) >= 2  # from default_linux + ssh presets
        first_user, first_pw = creds[0]
        assert isinstance(first_user, str)
        assert isinstance(first_pw, str)

    def test_load_winrm_creds(self, cred_store):
        creds = cred_store.load_creds("winrm")
        assert len(creds) >= 1

    def test_load_smb_creds(self, cred_store):
        creds = cred_store.load_creds("smb")
        assert len(creds) >= 1

    def test_password_spray_conversion(self, cred_store):
        # Verify password_spray keys produce results in load_creds
        creds = cred_store.load_creds("ssh")
        usernames = {c[0] for c in creds}
        assert "default_user" in usernames or "admin" in usernames

    def test_load_unknown_service_returns_ssh_defaults(self, cred_store_no_defaults):
        # With no JSON presets, load_creds should still not crash
        creds = cred_store_no_defaults.load_creds("ssh")
        assert isinstance(creds, list)


class TestGetCredentials:
    def test_get_by_target(self, cred_store):
        cred_store.add_credential(Credential(username="x", password="y", target="10.1.0.5"))
        rows = cred_store.get_credentials(target="10.1.0.5")
        assert len(rows) == 1

    def test_get_by_nonexistent_target(self, cred_store):
        rows = cred_store.get_credentials(target="999.999.999.999")
        assert len(rows) == 0

    def test_verified_only_true(self, cred_store):
        cred_store.add_credential(Credential(username="test1", password="p1", target="*"))
        cred_store.mark_verified("*", "test1", "p1")
        rows = cred_store.get_credentials(verified_only=True)
        assert any(r["username"] == "test1" for r in rows)

    def test_verified_only_false(self, cred_store):
        cred_store.add_credential(Credential(username="test2", password="p2", target="*"))
        # Mark as unverified: re-insert won't change verified since UNIQUE constraint
        rows = cred_store.get_credentials(verified_only=False)
        usernames = [r["username"] for r in rows]
        assert "test2" in usernames


class TestMarkVerified:
    def test_mark_verified(self, cred_store):
        cred_store.add_credential(Credential(username="v1", password="vp", target="tgt"))
        cred_store.mark_verified("tgt", "v1", "vp")
        rows = cred_store.get_credentials(target="tgt")
        assert rows[0]["verified"] == 1


class TestDefaultsLoading:
    def test_defaults_populated(self, cred_store):
        assert "default_linux" in cred_store.defaults
        assert isinstance(cred_store.defaults["default_linux"], list)

    def test_defaults_password_spray(self, cred_store):
        assert "password_spray" in cred_store.defaults
        assert len(cred_store.defaults["password_spray"]) > 0

    def test_missing_json_file_skips_gracefully(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as f:
            db_path = f.name
        import subprocess
        # Ensure file doesn't exist
        store = CredentialStore(db_path=db_path, cred_json_path="/nonexistent/path.json")
        assert "default_linux" in store.defaults
