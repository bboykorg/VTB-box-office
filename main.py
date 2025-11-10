from os import environ
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.secret_key = environ.get("APP_SECRET", "dev-secret-change-in-prod")

engine = create_engine('sqlite:///VTB.db')
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    balance = Column(Float, default=0.0)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Явно указываем foreign_keys для отношений
    transactions = relationship(
        "Transaction",
        foreign_keys="Transaction.user_id",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    # Отношение для входящих переводов
    incoming_transactions = relationship(
        "Transaction",
        foreign_keys="Transaction.target_id",
        back_populates="target_user"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Transaction(Base):
    __tablename__ = 'transactions'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    type = Column(String(20), nullable=False)
    amount = Column(Float, nullable=False)
    target_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    description = Column(String(200))

    # Явно указываем foreign_keys для отношений
    user = relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="transactions"
    )

    target_user = relationship(
        "User",
        foreign_keys=[target_id],
        back_populates="incoming_transactions"
    )


Base.metadata.create_all(engine)


@login_manager.user_loader
def load_user(user_id):
    db = SessionLocal()
    try:
        return db.query(User).get(int(user_id))
    finally:
        db.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_info():
    try:
        from zoneinfo import ZoneInfo
        now = datetime.now(ZoneInfo("Europe/Amsterdam"))
    except Exception:
        # Fallback для Windows без tzdata
        from datetime import timedelta
        now = datetime.utcnow() + timedelta(hours=1)

    return {
        "current_time": now.strftime("%B %d, %Y %I:%M %p CET"),
        "country": "NL"
    }


@app.context_processor
def inject_user_info():
    return get_user_info()


@app.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = next(get_db())
        user = db.query(User).filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("index"))
        flash("Неверный логин или пароль", "danger")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm_password = request.form.get("confirm_password", "")

        # Проверка совпадения паролей
        if password != confirm_password:
            return render_template("register.html", message="Пароли не совпадают")

        # Проверка длины пароля
        if len(password) < 4:
            return render_template("register.html", message="Пароль должен содержать не менее 4 символов")

        db = next(get_db())
        if db.query(User).filter_by(username=username).first():
            return render_template("register.html", message="Пользователь уже существует")

        user = User(username=username)
        user.set_password(password)
        db.add(user)
        try:
            db.commit()
            flash("Вы успешно зарегистрировались!", "success")
            return redirect(url_for("login"))
        except IntegrityError:
            db.rollback()
            return render_template("register.html", message="Ошибка при регистрации")
    return render_template('register.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/profile")
@login_required
def profile():
    db = next(get_db())
    transactions = db.query(Transaction).filter_by(user_id=current_user.id).order_by(
        Transaction.timestamp.desc()).limit(10).all()
    return render_template("profile.html", user=current_user, transactions=transactions)


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "POST":
        try:
            amount = float(request.form["amount"])
            if amount <= 0:
                flash("Сумма должна быть положительной", "danger")
            else:
                db = next(get_db())
                # Получаем пользователя из базы данных, а не используем current_user напрямую
                user = db.query(User).get(current_user.id)
                user.balance += amount
                tx = Transaction(
                    user_id=user.id,
                    type="deposit",
                    amount=amount,
                    description=f"Внесение {amount}"
                )
                db.add(tx)
                db.commit()
                flash(f"Внесено {amount}", "success")
                return redirect(url_for("profile"))
        except ValueError:
            flash("Некорректная сумма", "danger")
    return render_template("deposit.html")


@app.route("/withdraw", methods=["GET", "POST"])
@login_required
def withdraw():
    if request.method == "POST":
        try:
            amount = float(request.form["amount"])
            if amount <= 0:
                flash("Сумма должна быть положительной", "danger")
            elif amount > current_user.balance:
                flash("Недостаточно средств", "danger")
            else:
                db = next(get_db())
                # Получаем пользователя из базы данных
                user = db.query(User).get(current_user.id)
                user.balance -= amount
                tx = Transaction(
                    user_id=user.id,
                    type="withdraw",
                    amount=amount,
                    description=f"Снятие {amount}"
                )
                db.add(tx)
                db.commit()
                flash(f"Снято {amount}", "success")
                return redirect(url_for("profile"))
        except ValueError:
            flash("Некорректная сумма", "danger")
    return render_template("withdraw.html")


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    db = next(get_db())
    users = db.query(User).filter(User.id != current_user.id).all()
    if request.method == "POST":
        try:
            target_username = request.form["target"]
            amount = float(request.form["amount"])
            target = db.query(User).filter_by(username=target_username).first()

            if not target:
                flash("Получатель не найден", "danger")
            elif amount <= 0:
                flash("Сумма должна быть положительной", "danger")
            elif amount > current_user.balance:
                flash("Недостаточно средств", "danger")
            else:
                # Получаем обоих пользователей из базы данных
                sender = db.query(User).get(current_user.id)
                recipient = db.query(User).get(target.id)

                sender.balance -= amount
                recipient.balance += amount

                tx_out = Transaction(
                    user_id=sender.id,
                    type="transfer",
                    amount=amount,
                    target_id=recipient.id,
                    description=f"Перевод {amount} → {recipient.username}"
                )
                tx_in = Transaction(
                    user_id=recipient.id,
                    type="transfer",
                    amount=amount,
                    target_id=sender.id,
                    description=f"Получено {amount} от {sender.username}"
                )
                db.add_all([tx_out, tx_in])
                db.commit()
                flash(f"Переведено {amount} пользователю {recipient.username}", "success")
                return redirect(url_for("profile"))
        except ValueError:
            flash("Некорректная сумма", "danger")
    return render_template("transfer.html", users=users)


@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash("Доступ запрещён", "danger")
        return redirect(url_for("profile"))
    db = next(get_db())
    transactions = db.query(Transaction).order_by(Transaction.timestamp.desc()).all()
    users = db.query(User).all()
    return render_template("admin.html", transactions=transactions, users=users)

@app.route('/currency')
def currency():
    return render_template('currency.html')

@app.route('/deposit_calculator')
def deposit_calculator():
    return render_template('deposit_calculator.html')


with app.app_context():
    db = next(get_db())
    if not db.query(User).filter_by(username="admin").first():
        admin = User(username="admin", is_admin=True, balance=10000)
        admin.set_password("admin123")
        alice = User(username="alice", balance=500)
        alice.set_password("alice123")
        bob = User(username="bob", balance=300)
        bob.set_password("bob123")
        db.add_all([admin, alice, bob])
        db.commit()

if __name__ == "__main__":
    app.run(debug=True, port=5001)