import os
import uuid
from functools import wraps
from datetime import datetime, timezone

from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from extensions import db, login_manager
from models import User, Document, Permission, AuditLog

ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "doc", "docx", "xlsx", "csv"}
MAX_FILE_SIZE = 10 * 1024 * 1024


def create_app(test_config=None):
    app = Flask(__name__)
    database_url = os.environ.get("DATABASE_URL", "sqlite:///trustvault.db")
    # Some hosting dashboards still provide the legacy postgres:// scheme.
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret-before-deploy"),
        SQLALCHEMY_DATABASE_URI=database_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=MAX_FILE_SIZE,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
        UPLOAD_FOLDER=os.environ.get(
            "UPLOAD_FOLDER", os.path.join(app.instance_path, "private_uploads")
        ),
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message_category = "warning"
    CSRFProtect(app)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    def audit(action, target_type=None, target_id=None, details=""):
        entry = AuditLog(
            actor_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=(details or "")[:1000],
            # Do not trust a client-supplied X-Forwarded-For header by default.
            # Configure trusted-proxy handling explicitly if deployed behind a proxy.
            ip_address=(request.remote_addr or "")[:45],
        )
        db.session.add(entry)
        db.session.commit()

    def allowed_file(filename):
        return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

    def get_document_access(document):
        if current_user.role == "admin" or document.owner_id == current_user.id:
            return True, True
        permission = Permission.query.filter_by(
            user_id=current_user.id, document_id=document.id
        ).first()
        return (bool(permission and permission.can_read),
                bool(permission and permission.can_edit))

    def require_document_access(document, edit=False):
        can_read, can_edit = get_document_access(document)
        if not can_read or (edit and not can_edit):
            audit("DENIED_DOCUMENT_ACCESS", "document", document.id,
                  "edit" if edit else "read")
            abort(403)
        return can_edit

    @app.errorhandler(413)
    def too_large(_error):
        flash("File is too large. Maximum size is 10 MB.", "danger")
        return redirect(url_for("documents"))

    @app.route("/")
    def home():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if len(username) < 3 or len(password) < 8 or "@" not in email:
                flash("Enter a valid username/email and a password of at least 8 characters.", "danger")
                return render_template("register.html")
            if User.query.filter((User.username == username) | (User.email == email)).first():
                flash("Username or email already exists.", "danger")
                return render_template("register.html")
            # Public registration can create owners only. Admin is provisioned out-of-band.
            user = User(username=username, email=email,
                        password_hash=generate_password_hash(password), role="owner")
            db.session.add(user)
            db.session.commit()
            audit("USER_REGISTERED", "user", user.id, "owner account created")
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            identity = request.form.get("identity", "").strip()
            password = request.form.get("password", "")
            user = User.query.filter(
                (User.username == identity) | (User.email == identity.lower())
            ).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                audit("LOGIN_SUCCESS", "user", user.id)
                return redirect(url_for("dashboard"))
            audit("LOGIN_FAILED", "user", details=f"identity={identity[:100]}")
            flash("Invalid username/email or password.", "danger")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        audit("LOGOUT", "user", current_user.id)
        logout_user()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        if current_user.role == "admin":
            docs = Document.query.order_by(Document.created_at.desc()).all()
            logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(30).all()
        else:
            owned_ids = [d.id for d in Document.query.filter_by(owner_id=current_user.id).all()]
            permitted_ids = [p.document_id for p in Permission.query.filter_by(
                user_id=current_user.id, can_read=True).all()]
            ids = set(owned_ids + permitted_ids)
            docs = Document.query.filter(Document.id.in_(ids)).order_by(Document.created_at.desc()).all() if ids else []
            logs = []
        return render_template("dashboard.html", documents=docs, logs=logs)

    @app.route("/documents", methods=["GET", "POST"])
    @login_required
    def documents():
        if request.method == "POST":
            if current_user.role not in ("owner", "admin"):
                abort(403)
            uploaded = request.files.get("file")
            if not uploaded or not uploaded.filename:
                flash("Choose a file first.", "danger")
                return redirect(url_for("documents"))
            original = secure_filename(uploaded.filename)
            if not original or not allowed_file(original):
                flash("Unsupported file type.", "danger")
                return redirect(url_for("documents"))
            data = uploaded.read(MAX_FILE_SIZE + 1)
            if not data or len(data) > MAX_FILE_SIZE:
                flash("File is empty or exceeds 10 MB.", "danger")
                return redirect(url_for("documents"))
            stored = f"{uuid.uuid4().hex}_{original}"
            path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
            with open(path, "xb") as output:
                output.write(data)
            doc = Document(original_name=original, stored_name=stored,
                           file_size=len(data), owner_id=current_user.id)
            db.session.add(doc)
            db.session.commit()
            audit("DOCUMENT_UPLOADED", "document", doc.id, original)
            flash("Document uploaded successfully.", "success")
            return redirect(url_for("documents"))

        if current_user.role == "admin":
            docs = Document.query.order_by(Document.created_at.desc()).all()
        else:
            owned = Document.query.filter_by(owner_id=current_user.id).all()
            permitted = Permission.query.filter_by(user_id=current_user.id, can_read=True).all()
            ids = {d.id for d in owned} | {p.document_id for p in permitted}
            docs = Document.query.filter(Document.id.in_(ids)).order_by(Document.created_at.desc()).all() if ids else []
        query = request.args.get("q", "").strip().lower()
        if query:
            docs = [d for d in docs if query in d.original_name.lower()]
        return render_template("documents.html", documents=docs)

    @app.route("/documents/<int:document_id>/download")
    @login_required
    def download_document(document_id):
        doc = db.get_or_404(Document, document_id)
        require_document_access(doc, edit=False)
        audit("DOCUMENT_DOWNLOADED", "document", doc.id, doc.original_name)
        return send_from_directory(app.config["UPLOAD_FOLDER"], doc.stored_name,
                                   as_attachment=True, download_name=doc.original_name)

    @app.route("/documents/<int:document_id>/rename", methods=["POST"])
    @login_required
    def rename_document(document_id):
        doc = db.get_or_404(Document, document_id)
        require_document_access(doc, edit=True)
        new_name = secure_filename(request.form.get("name", "").strip())
        if not new_name:
            flash("Enter a valid filename.", "danger")
        else:
            old_name = doc.original_name
            doc.original_name = new_name
            db.session.commit()
            audit("DOCUMENT_RENAMED", "document", doc.id, f"{old_name} -> {new_name}")
            flash("Document renamed.", "success")
        return redirect(url_for("documents"))

    @app.route("/documents/<int:document_id>/delete", methods=["POST"])
    @login_required
    def delete_document(document_id):
        doc = db.get_or_404(Document, document_id)
        # Only owner/admin may delete; edit permission alone is not deletion permission.
        if current_user.role != "admin" and doc.owner_id != current_user.id:
            audit("DENIED_DELETE", "document", doc.id)
            abort(403)
        stored = doc.stored_name
        audit("DOCUMENT_DELETED", "document", doc.id, doc.original_name)
        Permission.query.filter_by(document_id=doc.id).delete()
        db.session.delete(doc)
        db.session.commit()
        try:
            os.remove(os.path.join(app.config["UPLOAD_FOLDER"], stored))
        except FileNotFoundError:
            pass
        flash("Document deleted.", "success")
        return redirect(url_for("documents"))

    @app.route("/documents/<int:document_id>/share", methods=["POST"])
    @login_required
    def share_document(document_id):
        doc = db.get_or_404(Document, document_id)
        if current_user.role != "admin" and doc.owner_id != current_user.id:
            audit("DENIED_PERMISSION_CHANGE", "document", doc.id)
            abort(403)
        target = User.query.filter_by(email=request.form.get("email", "").strip().lower()).first()
        if not target:
            flash("User not found.", "danger")
            return redirect(url_for("documents"))
        if target.id == doc.owner_id:
            flash("Owner already has full access.", "warning")
            return redirect(url_for("documents"))
        can_read = request.form.get("can_read") == "on"
        can_edit = request.form.get("can_edit") == "on"
        if can_edit:
            can_read = True
        permission = Permission.query.filter_by(user_id=target.id, document_id=doc.id).first()
        if not can_read:
            if permission:
                db.session.delete(permission)
                db.session.commit()
                audit("PERMISSION_REVOKED", "document", doc.id, target.email)
            else:
                flash("No permission existed for this user.", "warning")
                return redirect(url_for("documents"))
        else:
            if permission:
                permission.can_read, permission.can_edit = can_read, can_edit
                permission.granted_by = current_user.id
            else:
                permission = Permission(user_id=target.id, document_id=doc.id,
                                        can_read=can_read, can_edit=can_edit,
                                        granted_by=current_user.id)
                db.session.add(permission)
            db.session.commit()
            audit("PERMISSION_GRANTED_OR_UPDATED", "document", doc.id,
                  f"{target.email}; read={can_read}; edit={can_edit}")
        flash("Permission updated.", "success")
        return redirect(url_for("documents"))

    @app.route("/admin/audit")
    @login_required
    def audit_page():
        if current_user.role != "admin":
            abort(403)
        logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()
        return render_template("dashboard.html", documents=[], logs=logs, audit_only=True)

    @app.cli.command("create-admin")
    def create_admin():
        """Create an admin using ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD env vars."""
        username = os.environ.get("ADMIN_USERNAME")
        email = os.environ.get("ADMIN_EMAIL")
        password = os.environ.get("ADMIN_PASSWORD")
        if not all([username, email, password]) or len(password) < 12:
            raise SystemExit("Set ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD (12+ chars).")
        if User.query.filter((User.username == username) | (User.email == email.lower())).first():
            raise SystemExit("Admin username/email already exists.")
        user = User(username=username, email=email.lower(),
                    password_hash=generate_password_hash(password), role="admin")
        db.session.add(user)
        db.session.commit()
        print("Admin account created.")

    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
