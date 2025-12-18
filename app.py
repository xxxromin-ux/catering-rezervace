import os
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
from dateutil import parser

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from models import db, Reservation, Resource, User, ReservationSignup

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


class SessionUser(UserMixin):
    def __init__(self, username: str, role: str):
        self.id = username
        self.role = role


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("APP_SECRET", "change-me")

    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "reservations.sqlite3")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    # --------------------
    # helpers
    # --------------------
    def parse_dt(value: str) -> datetime:
        return parser.parse(value)

    def seed_defaults():
        if Resource.query.count() == 0:
            db.session.add(Resource(name="Tým A", kind="team", color="#0b57d0"))
            db.session.add(Resource(name="Tým B", kind="team", color="#9333ea"))
            db.session.add(Resource(name="Auto 1", kind="vehicle", color="#16a34a"))
            db.session.add(Resource(name="Kuchyně", kind="kitchen", color="#f59e0b"))
            db.session.commit()

    def has_conflict(resource_id: int, start: datetime, end: datetime, ignore_id=None) -> bool:
        q = Reservation.query.filter(
            Reservation.resource_id == resource_id,
            Reservation.start < end,
            Reservation.end > start,
            Reservation.status != "cancelled"
        )
        if ignore_id is not None:
            q = q.filter(Reservation.id != ignore_id)
        return q.first() is not None

    def require_admin():
        if not getattr(current_user, "is_authenticated", False):
            abort(401)
        if getattr(current_user, "role", "reader") != "admin":
            abort(403)

    def get_db_user() -> User | None:
        if not getattr(current_user, "is_authenticated", False):
            return None
        return User.query.filter_by(username=current_user.id).first()

    # --------------------
    # Email (SMTP)
    # --------------------
    def _smtp_enabled() -> bool:
        return bool(os.getenv("SMTP_HOST")) and bool(os.getenv("SMTP_FROM"))

    def send_email(to_addrs: list[str], subject: str, body: str) -> None:
        # Silent fail if not configured
        if not _smtp_enabled():
            return
        to_addrs = [x.strip() for x in to_addrs if x and x.strip()]
        if not to_addrs:
            return

        host = os.getenv("SMTP_HOST")
        port = int(os.getenv("SMTP_PORT", "587"))
        user = os.getenv("SMTP_USER", "")
        password = os.getenv("SMTP_PASS", "")
        from_addr = os.getenv("SMTP_FROM")
        use_tls = os.getenv("SMTP_TLS", "1") != "0"

        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = subject
        msg.set_content(body)

        try:
            if use_tls:
                with smtplib.SMTP(host, port, timeout=15) as s:
                    s.starttls()
                    if user and password:
                        s.login(user, password)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=15) as s:
                    if user and password:
                        s.login(user, password)
                    s.send_message(msg)
        except Exception:
            # nechceme shodit aplikaci kvůli mailu
            pass

    def admin_emails() -> list[str]:
        admins = User.query.filter_by(role="admin").all()
        return [a.email for a in admins if a.email]

    def notify_admins(subject: str, body: str) -> None:
        send_email(admin_emails(), subject, body)

    @login_manager.user_loader
    def load_user(username: str):
        u = User.query.filter_by(username=username).first()
        if not u:
            return None
        return SessionUser(u.username, u.role)

    with app.app_context():
        db.create_all()
        seed_defaults()

    # --------------------
    # Auth: login / logout / register
    # --------------------
    @app.get("/login")
    def login():
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        u = User.query.filter_by(username=username).first()
        if not u or not u.verify(password):
            flash("Špatné přihlašovací údaje.", "error")
            return redirect(url_for("login"))

        login_user(SessionUser(u.username, u.role))
        return redirect(url_for("calendar_view"))

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        # Registrace: první účet v DB => admin, další => reader
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip() or None
            password = request.form.get("password") or ""
            password2 = request.form.get("password2") or ""

            if not username or not password:
                flash("Vyplň uživatelské jméno a heslo.", "error")
                return redirect(url_for("register"))

            if password != password2:
                flash("Hesla se neshodují.", "error")
                return redirect(url_for("register"))

            if User.query.filter_by(username=username).first():
                flash("Uživatel už existuje.", "error")
                return redirect(url_for("register"))

            is_first = (User.query.count() == 0)
            role = "admin" if is_first else "reader"

            u = User.create(username=username, password=password, role=role, email=email)
            db.session.add(u)
            db.session.commit()

            # notifikace
            if u.email:
                send_email([u.email], "Catering: účet vytvořen",
                           f"Účet byl vytvořen.\n\nUživatel: {u.username}\nRole: {u.role}\n")
            notify_admins("Catering: nový účet",
                          f"Byl založen účet.\n\nUživatel: {u.username}\nRole: {u.role}\nEmail: {u.email or '-'}\n")

            flash("Registrace hotová. Můžeš se přihlásit.", "ok")
            return redirect(url_for("login"))

        return render_template("register.html")

    # --------------------
    # UI
    # --------------------
    @app.get("/")
    def root():
        if getattr(current_user, "is_authenticated", False):
            return redirect(url_for("calendar_view"))
        return redirect(url_for("login"))

    @app.get("/calendar")
    @login_required
    def calendar_view():
        resources = Resource.query.order_by(Resource.is_active.desc(), Resource.kind.asc(), Resource.name.asc()).all()
        selected = request.args.get("resource", "all")
        return render_template("calendar.html", resources=resources, selected=selected)

    # --------------------
    # API for FullCalendar
    # --------------------
    @app.get("/api/reservations")
    @login_required
    def api_reservations():
        resource = request.args.get("resource")
        start_q = request.args.get("start")
        end_q = request.args.get("end")

        q = Reservation.query

        if resource and resource != "all":
            try:
                rid = int(resource)
                q = q.filter(Reservation.resource_id == rid)
            except ValueError:
                pass

        if start_q and end_q:
            s = parse_dt(start_q)
            e = parse_dt(end_q)
            q = q.filter(Reservation.start < e, Reservation.end > s)

        items = q.order_by(Reservation.start.asc()).all()
        return jsonify([r.to_event() for r in items])

    # --------------------
    # Resources (admin only)
    # --------------------
    @app.get("/resources")
    @login_required
    def resources_list():
        require_admin()
        resources = Resource.query.order_by(Resource.is_active.desc(), Resource.kind.asc(), Resource.name.asc()).all()
        return render_template("resources.html", resources=resources)

    @app.route("/resources/new", methods=["GET", "POST"])
    @login_required
    def resource_new():
        require_admin()
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            kind = (request.form.get("kind") or "team").strip()
            is_active = (request.form.get("is_active") == "on")
            color = (request.form.get("color") or "#0b57d0").strip()

            if not name:
                flash("Chybí název zdroje.", "error")
                return redirect(url_for("resource_new"))

            if Resource.query.filter_by(name=name).first():
                flash("Zdroj s tímto názvem už existuje.", "error")
                return redirect(url_for("resource_new"))

            r = Resource(name=name, kind=kind, is_active=is_active, color=color)
            db.session.add(r)
            db.session.commit()
            flash("Zdroj přidán.", "ok")
            return redirect(url_for("resources_list"))

        return render_template("resource_form.html", mode="new", r=None)

    @app.route("/resources/<int:rid>/edit", methods=["GET", "POST"])
    @login_required
    def resource_edit(rid: int):
        require_admin()
        r = Resource.query.get_or_404(rid)

        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            kind = (request.form.get("kind") or r.kind).strip()
            is_active = (request.form.get("is_active") == "on")
            color = (request.form.get("color") or r.color or "#0b57d0").strip()

            if not name:
                flash("Chybí název zdroje.", "error")
                return redirect(url_for("resource_edit", rid=rid))

            other = Resource.query.filter(Resource.name == name, Resource.id != rid).first()
            if other:
                flash("Jiný zdroj s tímto názvem už existuje.", "error")
                return redirect(url_for("resource_edit", rid=rid))

            r.name = name
            r.kind = kind
            r.is_active = is_active
            r.color = color
            db.session.commit()
            flash("Zdroj upraven.", "ok")
            return redirect(url_for("resources_list"))

        return render_template("resource_form.html", mode="edit", r=r)

    @app.post("/resources/<int:rid>/toggle")
    @login_required
    def resource_toggle(rid: int):
        require_admin()
        r = Resource.query.get_or_404(rid)
        r.is_active = not r.is_active
        db.session.commit()
        flash("Stav zdroje změněn.", "ok")
        return redirect(url_for("resources_list"))

    # --------------------
    # Create reservation (admin only)
    # --------------------
    @app.route("/reservations/new", methods=["GET", "POST"])
    @login_required
    def new_reservation():
        require_admin()
        resources = Resource.query.filter_by(is_active=True).order_by(Resource.kind.asc(), Resource.name.asc()).all()

        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            start_raw = (request.form.get("start") or "").strip()
            end_raw = (request.form.get("end") or "").strip()
            resource_id_raw = request.form.get("resource_id") or ""

            if not title:
                flash("Chybí název akce.", "error")
                return redirect(url_for("new_reservation"))

            try:
                resource_id = int(resource_id_raw)
            except ValueError:
                flash("Vyber zdroj (tým/auto/kuchyně).", "error")
                return redirect(url_for("new_reservation"))

            try:
                start = parse_dt(start_raw)
                end = parse_dt(end_raw)
            except Exception:
                flash("Neplatný datum/čas.", "error")
                return redirect(url_for("new_reservation"))

            if end <= start:
                flash("Konec musí být po začátku.", "error")
                return redirect(url_for("new_reservation"))

            if has_conflict(resource_id, start, end):
                flash("Termín je obsazený pro zvolený zdroj (kolize).", "error")
                return redirect(url_for("new_reservation"))

            guests_val = request.form.get("guests")
            guests = int(guests_val) if guests_val else None

            rr = Reservation(
                resource_id=resource_id,
                title=title,
                start=start,
                end=end,
                client=request.form.get("client") or None,
                contact=request.form.get("contact") or None,
                location=request.form.get("location") or None,
                guests=guests,
                note=request.form.get("note") or None,
                status=request.form.get("status") or "confirmed",
            )

            db.session.add(rr)
            db.session.commit()

            # mail notifikace adminům
            res = Resource.query.get(resource_id)
            notify_admins(
                "Catering: nová rezervace",
                f"Nová rezervace byla vytvořena.\n\n"
                f"Akce: {rr.title}\n"
                f"Zdroj: {res.name if res else resource_id}\n"
                f"Čas: {rr.start} – {rr.end}\n"
                f"Místo: {rr.location or '-'}\n"
            )

            flash("Rezervace uložena.", "ok")
            return redirect(url_for("calendar_view"))

        return render_template("new.html", resources=resources)

    # --------------------
    # Detail + brigádnické přihlášky
    # --------------------
    @app.get("/reservations/<int:rid>")
    @login_required
    def detail(rid):
        r = Reservation.query.get_or_404(rid)
        u = get_db_user()
        is_signed = False
        if u:
            is_signed = ReservationSignup.query.filter_by(reservation_id=r.id, user_id=u.id).first() is not None
        signups = ReservationSignup.query.filter_by(reservation_id=r.id).all()
        return render_template("detail.html", r=r, is_signed=is_signed, signups=signups)

    @app.post("/reservations/<int:rid>/signup")
    @login_required
    def signup(rid: int):
        r = Reservation.query.get_or_404(rid)
        u = get_db_user()
        if not u:
            abort(401)

        if u.role == "admin":
            flash("Admin se nepřihlašuje jako brigádník.", "error")
            return redirect(url_for("detail", rid=rid))

        existing = ReservationSignup.query.filter_by(reservation_id=r.id, user_id=u.id).first()
        if existing:
            flash("Už jsi na akci přihlášen.", "ok")
            return redirect(url_for("detail", rid=rid))

        s = ReservationSignup(reservation_id=r.id, user_id=u.id)
        db.session.add(s)
        db.session.commit()

        # mail adminům + uživateli
        notify_admins(
            "Catering: brigádník přihlášen",
            f"Na akci se přihlásil brigádník.\n\n"
            f"Uživatel: {u.username}\nEmail: {u.email or '-'}\n"
            f"Akce: {r.title}\nZdroj: {r.resource.name}\n"
            f"Čas: {r.start} – {r.end}\n"
        )
        if u.email:
            send_email([u.email], "Catering: přihlášení na akci",
                       f"Jsi přihlášen na akci:\n\n{r.title}\n{r.start} – {r.end}\nZdroj: {r.resource.name}\n")

        flash("Přihlášení na akci uloženo.", "ok")
        return redirect(url_for("detail", rid=rid))

    @app.post("/reservations/<int:rid>/unsign")
    @login_required
    def unsign(rid: int):
        r = Reservation.query.get_or_404(rid)
        u = get_db_user()
        if not u:
            abort(401)

        row = ReservationSignup.query.filter_by(reservation_id=r.id, user_id=u.id).first()
        if not row:
            flash("Na akci nejsi přihlášen.", "error")
            return redirect(url_for("detail", rid=rid))

        db.session.delete(row)
        db.session.commit()

        notify_admins(
            "Catering: brigádník odhlášen",
            f"Brigádník se odhlásil.\n\nUživatel: {u.username}\nAkce: {r.title}\n"
        )
        flash("Odhlášení hotové.", "ok")
        return redirect(url_for("detail", rid=rid))

    # --------------------
    # Edit / cancel / delete (admin only)
    # --------------------
    @app.route("/reservations/<int:rid>/edit", methods=["GET", "POST"])
    @login_required
    def edit(rid):
        require_admin()
        r = Reservation.query.get_or_404(rid)
        resources = Resource.query.filter_by(is_active=True).order_by(Resource.kind.asc(), Resource.name.asc()).all()

        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            start_raw = (request.form.get("start") or "").strip()
            end_raw = (request.form.get("end") or "").strip()
            resource_id_raw = request.form.get("resource_id") or ""

            if not title:
                flash("Chybí název akce.", "error")
                return redirect(url_for("edit", rid=rid))

            try:
                resource_id = int(resource_id_raw)
            except ValueError:
                flash("Vyber zdroj.", "error")
                return redirect(url_for("edit", rid=rid))

            try:
                start = parse_dt(start_raw)
                end = parse_dt(end_raw)
            except Exception:
                flash("Neplatný datum/čas.", "error")
                return redirect(url_for("edit", rid=rid))

            if end <= start:
                flash("Konec musí být po začátku.", "error")
                return redirect(url_for("edit", rid=rid))

            if has_conflict(resource_id, start, end, ignore_id=rid):
                flash("Termín je obsazený pro zvolený zdroj (kolize).", "error")
                return redirect(url_for("edit", rid=rid))

            guests_val = request.form.get("guests")
            guests = int(guests_val) if guests_val else None

            r.resource_id = resource_id
            r.title = title
            r.start = start
            r.end = end
            r.client = request.form.get("client") or None
            r.contact = request.form.get("contact") or None
            r.location = request.form.get("location") or None
            r.guests = guests
            r.note = request.form.get("note") or None
            r.status = request.form.get("status") or r.status

            db.session.commit()
            flash("Rezervace upravena.", "ok")
            return redirect(url_for("detail", rid=rid))

        return render_template("edit.html", r=r, resources=resources)

    @app.post("/reservations/<int:rid>/cancel")
    @login_required
    def cancel(rid):
        require_admin()
        r = Reservation.query.get_or_404(rid)
        r.status = "cancelled"
        db.session.commit()
        flash("Rezervace zrušena.", "ok")
        return redirect(url_for("detail", rid=rid))

    @app.post("/reservations/<int:rid>/delete")
    @login_required
    def delete(rid):
        require_admin()
        r = Reservation.query.get_or_404(rid)
        db.session.delete(r)
        db.session.commit()
        flash("Rezervace smazána.", "ok")
        return redirect(url_for("calendar_view"))

    # --------------------
    # Admin: Users (ruční registrace + mazání)
    # --------------------
    @app.get("/admin/users")
    @login_required
    def admin_users():
        require_admin()
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template("admin_users.html", users=users)

    @app.route("/admin/users/new", methods=["GET", "POST"])
    @login_required
    def admin_user_new():
        require_admin()
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip() or None
            role = (request.form.get("role") or "reader").strip()
            password = request.form.get("password") or ""
            password2 = request.form.get("password2") or ""

            if not username or not password:
                flash("Chybí username/heslo.", "error")
                return redirect(url_for("admin_user_new"))
            if password != password2:
                flash("Hesla se neshodují.", "error")
                return redirect(url_for("admin_user_new"))
            if User.query.filter_by(username=username).first():
                flash("Uživatel už existuje.", "error")
                return redirect(url_for("admin_user_new"))

            u = User.create(username=username, password=password, role=role, email=email)
            db.session.add(u)
            db.session.commit()

            if u.email:
                send_email([u.email], "Catering: účet vytvořen adminem",
                           f"Byl ti vytvořen účet.\n\nUživatel: {u.username}\nRole: {u.role}\n")
            notify_admins("Catering: účet vytvořen adminem",
                          f"Admin vytvořil účet.\nUživatel: {u.username}\nRole: {u.role}\nEmail: {u.email or '-'}\n")

            flash("Uživatel vytvořen.", "ok")
            return redirect(url_for("admin_users"))

        return render_template("admin_user_form.html", mode="new", u=None)

    @app.post("/admin/users/<int:uid>/delete")
    @login_required
    def admin_user_delete(uid: int):
        require_admin()
        u = User.query.get_or_404(uid)

        # nedovol smazat posledního admina
        if u.role == "admin":
            admins = User.query.filter_by(role="admin").count()
            if admins <= 1:
                flash("Nelze smazat posledního admina.", "error")
                return redirect(url_for("admin_users"))

        # notifikace před smazáním
        if u.email:
            send_email([u.email], "Catering: účet smazán",
                       f"Tvůj účet byl smazán administrátorem.\n\nUživatel: {u.username}\n")
        notify_admins("Catering: účet smazán",
                      f"Byl smazán účet.\n\nUživatel: {u.username}\nRole: {u.role}\nEmail: {u.email or '-'}\n")

        db.session.delete(u)
        db.session.commit()
        flash("Uživatel smazán.", "ok")
        return redirect(url_for("admin_users"))

    # --------------------
    # Admin: přehled brigádníků
    # --------------------
    @app.get("/admin/signups")
    @login_required
    def admin_signups():
        require_admin()
        now = datetime.now()
        items = Reservation.query.filter(Reservation.end > now).order_by(Reservation.start.asc()).all()
        return render_template("admin_signups.html", items=items)

    # --------------------
    # Moje akce (brigádník)
    # --------------------
    @app.get("/me")
    @login_required
    def me():
        u = get_db_user()
        if not u:
            abort(401)

        if u.role == "admin":
            return redirect(url_for("calendar_view"))

        rows = ReservationSignup.query.filter_by(user_id=u.id).all()
        res_ids = [r.reservation_id for r in rows]
        items = []
        if res_ids:
            items = Reservation.query.filter(Reservation.id.in_(res_ids)).order_by(Reservation.start.asc()).all()
        return render_template("me.html", items=items)

    # --------------------
    # Agenda / Print / PDF
    # --------------------
    def _range(mode: str):
        now = datetime.now()
        if mode == "tomorrow":
            start = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=1)
            title = "Zítra"
        elif mode == "week":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=7)
            title = "Tento týden (7 dní)"
        else:
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=1)
            title = "Dnes"
        return start, end, title

    @app.get("/agenda")
    @login_required
    def agenda():
        mode = request.args.get("mode", "today")
        resource = request.args.get("resource", "all")
        start, end, title = _range(mode)

        q = Reservation.query.filter(Reservation.start < end, Reservation.end > start).order_by(Reservation.start.asc())
        if resource != "all":
            try:
                rid = int(resource)
                q = q.filter(Reservation.resource_id == rid)
            except ValueError:
                pass

        items = q.all()
        resources = Resource.query.filter_by(is_active=True).order_by(Resource.kind.asc(), Resource.name.asc()).all()
        return render_template("agenda.html", title=title, items=items, resources=resources, selected=resource, mode=mode)

    @app.get("/print")
    @login_required
    def print_view():
        mode = request.args.get("mode", "today")
        resource = request.args.get("resource", "all")
        start, end, title = _range(mode)

        q = Reservation.query.filter(Reservation.start < end, Reservation.end > start).order_by(Reservation.start.asc())
        if resource != "all":
            try:
                rid = int(resource)
                q = q.filter(Reservation.resource_id == rid)
            except ValueError:
                pass

        items = q.all()
        return render_template("print.html", title=title, items=items)

    @app.get("/export.pdf")
    @login_required
    def export_pdf():
        mode = request.args.get("mode", "today")
        resource = request.args.get("resource", "all")
        start, end, title = _range(mode)

        q = Reservation.query.filter(Reservation.start < end, Reservation.end > start).order_by(Reservation.start.asc())
        if resource != "all":
            try:
                rid = int(resource)
                q = q.filter(Reservation.resource_id == rid)
            except ValueError:
                pass

        items = q.all()

        out_path = "/tmp/catering_export.pdf"
        c = canvas.Canvas(out_path, pagesize=A4)
        width, height = A4

        y = height - 50
        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, f"Catering - přehled: {title}")
        y -= 25

        c.setFont("Helvetica", 10)
        for rr in items:
            line = f"{rr.start.strftime('%Y-%m-%d %H:%M')} - {rr.end.strftime('%H:%M')} | {rr.resource.name} | {rr.title}"
            if rr.location:
                line += f" | {rr.location}"
            c.drawString(40, y, line[:120])
            y -= 14
            if y < 60:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 10)

        c.save()
        return send_file(out_path, as_attachment=True, download_name="catering_export.pdf")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
