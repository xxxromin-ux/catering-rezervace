import os
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

    def parse_dt(value: str) -> datetime:
        return parser.parse(value)

    def seed_defaults():
        if Resource.query.count() == 0:
            db.session.add(Resource(name="Tým A", kind="team"))
            db.session.add(Resource(name="Tým B", kind="team"))
            db.session.add(Resource(name="Auto 1", kind="vehicle"))
            db.session.add(Resource(name="Kuchyně", kind="kitchen"))
            db.session.commit()

    def ensure_schema():
        # bezpečné ALTER TABLE (ignoruje chyby když už sloupec existuje)
        import sqlite3
        db_path = os.path.join(BASE_DIR, "reservations.sqlite3")
        if not os.path.exists(db_path):
            return
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        def try_sql(sql):
            try:
                cur.execute(sql)
            except Exception:
                pass

        # users profile + email
        try_sql("ALTER TABLE users ADD COLUMN email VARCHAR(200)")
        try_sql("ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1")
        try_sql("ALTER TABLE users ADD COLUMN full_name VARCHAR(200)")
        try_sql("ALTER TABLE users ADD COLUMN phone VARCHAR(80)")
        try_sql("ALTER TABLE users ADD COLUMN address VARCHAR(240)")
        try_sql("ALTER TABLE users ADD COLUMN note TEXT")

        # signups hours/role
        try_sql("ALTER TABLE reservation_signups ADD COLUMN hours REAL")
        try_sql("ALTER TABLE reservation_signups ADD COLUMN role_note VARCHAR(240)")
        try_sql("ALTER TABLE reservation_signups ADD COLUMN approved BOOLEAN NOT NULL DEFAULT 1")

        conn.commit()
        conn.close()

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

    def month_range(yyyy_mm: str):
        y, m = yyyy_mm.split("-")
        y = int(y); m = int(m)
        start = datetime(y, m, 1, 0, 0, 0)
        if m == 12:
            end = datetime(y + 1, 1, 1, 0, 0, 0)
        else:
            end = datetime(y, m + 1, 1, 0, 0, 0)
        return start, end

    @login_manager.user_loader
    def load_user(username: str):
        u = User.query.filter_by(username=username).first()
        if not u:
            return None
        return SessionUser(u.username, u.role)

    with app.app_context():
        db.create_all()
        ensure_schema()
        seed_defaults()

    # --------------------
    # Auth
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
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
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

            u = User.create(username=username, password=password, role=role)
            db.session.add(u)
            db.session.commit()

            flash("Registrace hotová. Můžeš se přihlásit.", "ok")
            return redirect(url_for("login"))

        return render_template("register.html")

    # --------------------
    # Root
    # --------------------
    @app.get("/")
    def root():
        if getattr(current_user, "is_authenticated", False):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    # --------------------
    # Dashboard
    # --------------------
    @app.get("/dashboard")
    @login_required
    def dashboard():
        now = datetime.now()
        month = request.args.get("month", now.strftime("%Y-%m"))
        ms, me = month_range(month)

        if current_user.role == "admin":
            upcoming = Reservation.query.filter(
                Reservation.end >= now,
                Reservation.status != "cancelled"
            ).order_by(Reservation.start.asc()).limit(50).all()

            total_hours = db.session.query(db.func.coalesce(db.func.sum(ReservationSignup.hours), 0.0))\
                .join(Reservation, Reservation.id == ReservationSignup.reservation_id)\
                .filter(Reservation.start >= ms, Reservation.start < me, Reservation.status != "cancelled")\
                .scalar()

            return render_template("dashboard_admin.html", upcoming=upcoming, month=month, total_hours=total_hours)

        my_upcoming = Reservation.query\
            .join(ReservationSignup, ReservationSignup.reservation_id == Reservation.id)\
            .join(User, User.id == ReservationSignup.user_id)\
            .filter(User.username == current_user.id, Reservation.end >= now, Reservation.status != "cancelled")\
            .order_by(Reservation.start.asc()).all()

        available = Reservation.query\
            .filter(Reservation.end >= now, Reservation.status != "cancelled")\
            .order_by(Reservation.start.asc()).limit(60).all()

        return render_template("dashboard_user.html", my_upcoming=my_upcoming, available=available)

    # --------------------
    # Profile (self)
    # --------------------
    @app.route("/me", methods=["GET", "POST"])
    @login_required
    def me():
        u = User.query.filter_by(username=current_user.id).first_or_404()

        if request.method == "POST":
            u.full_name = (request.form.get("full_name") or "").strip() or None
            u.email = (request.form.get("email") or "").strip() or None
            u.phone = (request.form.get("phone") or "").strip() or None
            u.address = (request.form.get("address") or "").strip() or None
            u.note = (request.form.get("note") or "").strip() or None
            db.session.commit()
            flash("Profil uložen.", "ok")
            return redirect(url_for("me"))

        return render_template("me.html", u=u)

    # --------------------
    # Calendar
    # --------------------
    @app.get("/calendar")
    @login_required
    def calendar_view():
        resources = Resource.query.order_by(Resource.is_active.desc(), Resource.kind.asc(), Resource.name.asc()).all()
        selected = request.args.get("resource", "all")
        return render_template("calendar.html", resources=resources, selected=selected)

    # --------------------
    # Resources (admin)
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
            color = (request.form.get("color") or "#0b57d0").strip() or "#0b57d0"

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
            color = (request.form.get("color") or r.color or "#0b57d0").strip() or "#0b57d0"

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
    # API events
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
    # Create reservation (admin)
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
            flash("Rezervace uložena.", "ok")
            return redirect(url_for("calendar_view"))

        return render_template("new.html", resources=resources)

    # --------------------
    # Detail reservation + signups
    # --------------------
    @app.get("/reservations/<int:rid>")
    @login_required
    def detail(rid):
        r = Reservation.query.get_or_404(rid)

        signups = ReservationSignup.query.filter_by(reservation_id=rid)\
            .join(User, User.id == ReservationSignup.user_id)\
            .order_by(User.username.asc()).all()

        all_users = []
        if current_user.role == "admin":
            all_users = User.query.filter_by(role="reader").order_by(User.username.asc()).all()

        me_u = User.query.filter_by(username=current_user.id).first()
        me_signed = False
        if me_u:
            me_signed = ReservationSignup.query.filter_by(reservation_id=rid, user_id=me_u.id).first() is not None

        return render_template("detail.html", r=r, signups=signups, all_users=all_users, me_signed=me_signed)

    # Brigádník signup / unsign
    @app.post("/reservations/<int:rid>/signup")
    @login_required
    def reservation_signup(rid: int):
        r = Reservation.query.get_or_404(rid)
        if r.status == "cancelled":
            abort(400)

        u = User.query.filter_by(username=current_user.id).first_or_404()
        s = ReservationSignup.query.filter_by(reservation_id=rid, user_id=u.id).first()
        if s:
            flash("Už jsi přihlášen/a.", "ok")
            return redirect(url_for("detail", rid=rid))

        db.session.add(ReservationSignup(reservation_id=rid, user_id=u.id, approved=True))
        db.session.commit()
        flash("Přihlášení na akci uloženo.", "ok")
        return redirect(url_for("detail", rid=rid))

    @app.post("/reservations/<int:rid>/unsign")
    @login_required
    def reservation_unsign(rid: int):
        u = User.query.filter_by(username=current_user.id).first_or_404()
        s = ReservationSignup.query.filter_by(reservation_id=rid, user_id=u.id).first()
        if not s:
            flash("Nejsi přihlášen/a.", "error")
            return redirect(url_for("detail", rid=rid))
        db.session.delete(s)
        db.session.commit()
        flash("Odhlášení z akce uloženo.", "ok")
        return redirect(url_for("detail", rid=rid))

    # Admin: add/remove/hours
    @app.post("/reservations/<int:rid>/admin/add_signup")
    @login_required
    def admin_add_signup(rid: int):
        require_admin()
        user_id = request.form.get("user_id")
        try:
            uid = int(user_id)
        except Exception:
            flash("Neplatný uživatel.", "error")
            return redirect(url_for("detail", rid=rid))

        if ReservationSignup.query.filter_by(reservation_id=rid, user_id=uid).first():
            flash("Uživatel už je přihlášen.", "ok")
            return redirect(url_for("detail", rid=rid))

        db.session.add(ReservationSignup(reservation_id=rid, user_id=uid, approved=True))
        db.session.commit()
        flash("Brigádník přidán.", "ok")
        return redirect(url_for("detail", rid=rid))

    @app.post("/reservations/<int:rid>/admin/remove_signup")
    @login_required
    def admin_remove_signup(rid: int):
        require_admin()
        sid = int(request.form.get("signup_id"))
        s = ReservationSignup.query.get_or_404(sid)
        if s.reservation_id != rid:
            abort(400)
        db.session.delete(s)
        db.session.commit()
        flash("Brigádník odebrán.", "ok")
        return redirect(url_for("detail", rid=rid))

    @app.post("/reservations/<int:rid>/admin/set_hours")
    @login_required
    def admin_set_hours(rid: int):
        require_admin()
        sid = int(request.form.get("signup_id"))
        hours_raw = (request.form.get("hours") or "").replace(",", ".").strip()
        role_note = (request.form.get("role_note") or "").strip() or None

        s = ReservationSignup.query.get_or_404(sid)
        if s.reservation_id != rid:
            abort(400)

        if hours_raw:
            try:
                s.hours = float(hours_raw)
            except Exception:
                flash("Hodiny musí být číslo.", "error")
                return redirect(url_for("detail", rid=rid))
        else:
            s.hours = None

        s.role_note = role_note
        db.session.commit()
        flash("Hodiny uloženy.", "ok")
        return redirect(url_for("detail", rid=rid))

    # Admin users list + detail hours per month
    @app.get("/admin/users")
    @login_required
    def admin_users():
        require_admin()
        users = User.query.order_by(User.role.asc(), User.username.asc()).all()
        return render_template("admin_users.html", users=users)

    @app.get("/admin/users/<int:uid>")
    @login_required
    def admin_user_detail(uid: int):
        require_admin()
        u = User.query.get_or_404(uid)

        now = datetime.now()
        month = request.args.get("month", now.strftime("%Y-%m"))
        ms, me = month_range(month)

        rows = db.session.query(
            Reservation.id.label("id"),
            Reservation.title.label("title"),
            Reservation.start.label("start"),
            Reservation.end.label("end"),
            Resource.name.label("name"),
            ReservationSignup.hours.label("hours"),
            ReservationSignup.role_note.label("role_note"),
        )\
        .join(Reservation, Reservation.id == ReservationSignup.reservation_id)\
        .join(Resource, Resource.id == Reservation.resource_id)\
        .filter(ReservationSignup.user_id == uid, Reservation.start >= ms, Reservation.start < me, Reservation.status != "cancelled")\
        .order_by(Reservation.start.asc()).all()

        total = 0.0
        for row in rows:
            if row.hours is not None:
                total += float(row.hours)

        return render_template("admin_user_detail.html", u=u, month=month, rows=rows, total=total)

    # --------------------
    # Edit / cancel / delete reservation (admin)
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
