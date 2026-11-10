import io
import pytest
from werkzeug.security import generate_password_hash
from app import create_app
from extensions import db
from models import User, Document, Permission, AuditLog


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(tmp_path / "test.db"),
        "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        "SECRET_KEY": "test-secret",
    })
    with app.app_context():
        db.drop_all()
        db.create_all()
        owner = User(username="owner1", email="owner@example.com",
                     password_hash=generate_password_hash("password123"), role="owner")
        viewer = User(username="viewer1", email="viewer@example.com",
                      password_hash=generate_password_hash("password123"), role="owner")
        editor = User(username="editor1", email="editor@example.com",
                      password_hash=generate_password_hash("password123"), role="owner")
        admin = User(username="admin1", email="admin@example.com",
                     password_hash=generate_password_hash("password123"), role="admin")
        db.session.add_all([owner, viewer, editor, admin])
        db.session.commit()
        doc = Document(original_name="private.txt", stored_name="private.txt",
                       file_size=6, owner_id=owner.id)
        db.session.add(doc)
        db.session.commit()
        db.session.add_all([
            Permission(user_id=viewer.id, document_id=doc.id, can_read=True,
                       can_edit=False, granted_by=owner.id),
            Permission(user_id=editor.id, document_id=doc.id, can_read=True,
                       can_edit=True, granted_by=owner.id),
        ])
        db.session.commit()
        with open(app.config["UPLOAD_FOLDER"] + "/private.txt", "wb") as f:
            f.write(b"secret")
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


def login(client, username):
    return client.post("/login", data={"identity": username, "password": "password123"})


def test_unshared_user_cannot_download(app):
    client = app.test_client()
    login(client, "viewer1")
    # This fixture's viewer is shared; use a separate unshared account.
    with app.app_context():
        user = User(username="outsider", email="out@example.com",
                    password_hash=generate_password_hash("password123"), role="owner")
        db.session.add(user)
        db.session.commit()
    client = app.test_client()
    login(client, "outsider")
    assert client.get("/documents/1/download").status_code == 403


def test_viewer_can_download_but_cannot_rename_or_delete(app):
    client = app.test_client()
    login(client, "viewer1")
    assert client.get("/documents/1/download").status_code == 200
    assert client.post("/documents/1/rename", data={"name": "changed.txt"}).status_code == 403
    assert client.post("/documents/1/delete").status_code == 403


def test_editor_can_rename_but_cannot_delete_or_share(app):
    client = app.test_client()
    login(client, "editor1")
    assert client.post("/documents/1/rename", data={"name": "updated.txt"}).status_code == 302
    assert client.post("/documents/1/delete").status_code == 403
    assert client.post("/documents/1/share", data={"email": "viewer@example.com", "can_read": "on"}).status_code == 403


def test_non_owner_cannot_change_permissions(app):
    client = app.test_client()
    login(client, "viewer1")
    assert client.post("/documents/1/share", data={"email": "editor@example.com", "can_read": "on"}).status_code == 403


def test_admin_can_download_document(app):
    client = app.test_client()
    login(client, "admin1")
    assert client.get("/documents/1/download").status_code == 200


def test_public_registration_cannot_assign_admin_role(app):
    client = app.test_client()
    response = client.post("/register", data={
        "username": "attacker", "email": "attacker@example.com",
        "password": "password123", "role": "admin"
    })
    assert response.status_code == 302
    with app.app_context():
        user = User.query.filter_by(username="attacker").first()
        assert user is not None
        assert user.role == "owner"


def test_upload_rejects_disallowed_extension(app):
    client = app.test_client()
    login(client, "owner1")
    response = client.post("/documents", data={
        "file": (io.BytesIO(b"not really an executable"), "bad.exe")
    }, content_type="multipart/form-data")
    assert response.status_code == 302
    with app.app_context():
        assert Document.query.count() == 1


def test_upload_accepts_allowed_file_and_records_audit(app):
    client = app.test_client()
    login(client, "owner1")
    response = client.post("/documents", data={
        "file": (io.BytesIO(b"hello document"), "notes.txt")
    }, content_type="multipart/form-data")
    assert response.status_code == 302
    with app.app_context():
        assert Document.query.count() == 2
        assert AuditLog.query.filter_by(action="DOCUMENT_UPLOADED").count() == 1


def test_denied_access_is_audited(app):
    with app.app_context():
        outsider = User(username="outsider2", email="out2@example.com",
                        password_hash=generate_password_hash("password123"), role="owner")
        db.session.add(outsider)
        db.session.commit()
    client = app.test_client()
    login(client, "outsider2")
    assert client.get("/documents/1/download").status_code == 403
    with app.app_context():
        assert AuditLog.query.filter_by(action="DENIED_DOCUMENT_ACCESS").count() == 1


def test_login_success_is_audited(app):
    client = app.test_client()
    login(client, "owner1")
    with app.app_context():
        assert AuditLog.query.filter_by(action="LOGIN_SUCCESS").count() == 1


def test_non_admin_cannot_view_audit_page(app):
    client = app.test_client()
    login(client, "owner1")
    assert client.get("/admin/audit").status_code == 403


def test_owner_can_revoke_viewer_permission(app):
    client = app.test_client()
    login(client, "owner1")
    response = client.post("/documents/1/share", data={"email": "viewer@example.com"})
    assert response.status_code == 302
    viewer_client = app.test_client()
    login(viewer_client, "viewer1")
    assert viewer_client.get("/documents/1/download").status_code == 403
    with app.app_context():
        assert AuditLog.query.filter_by(action="PERMISSION_REVOKED").count() == 1
