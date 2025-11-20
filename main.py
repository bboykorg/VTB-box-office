import os
import re
import requests
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.exc import IntegrityError

# Конфигурация
class Config:
    SECRET_KEY = os.environ.get("APP_SECRET", "dev-secret-change-in-prod")
    DATABASE_URL = 'sqlite:///VTB.db'
    OLLAMA_URL = "http://localhost:11434"
    OLLAMA_MODEL = "deepseek-r1:8b"
    MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY")
    MISTRAL_MODEL = "mistral-large-latest"

# Инициализация приложения
app = Flask(__name__)
app.config.from_object(Config)

# Инициализация базы данных
engine = create_engine(Config.DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Инициализация аутентификации
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Модели базы данных
class User(Base, UserMixin):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    balance = Column(Float, default=0.0)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    phone_number = Column(String(20), nullable=False)

    transactions = relationship(
        "Transaction",
        foreign_keys="Transaction.user_id",
        back_populates="user",
        cascade="all, delete-orphan"
    )

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

# Вспомогательные функции
class AIAssistant:
    def __init__(self):
        self.mistral_client = self._init_mistral()
    
    def _init_mistral(self):
        """Инициализация клиента Mistral"""
        if not Config.MISTRAL_API_KEY:
            print("Предупреждение: MISTRAL_API_KEY не задан")
            return None
        
        try:
            from mistralai import Mistral
            return Mistral(api_key=Config.MISTRAL_API_KEY)
        except ImportError:
            print("Библиотека mistralai не установлена")
            return None
        except Exception as e:
            print(f"Ошибка инициализации Mistral: {e}")
            return None
    
    def query_ollama(self, prompt):
        """Запрос к Ollama"""
        try:
            payload = {
                "model": Config.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.7, "top_p": 0.9, "top_k": 40}
            }

            response = requests.post(
                f"{Config.OLLAMA_URL}/api/generate",
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                return response.json().get("response", "").strip()
            else:
                print(f"Ошибка Ollama: {response.status_code}")
                return None

        except requests.exceptions.ConnectionError:
            print("Ollama не доступен")
            return None
        except Exception as e:
            print(f"Ошибка запроса к Ollama: {e}")
            return None
    
    def query_mistral(self, prompt):
        """Запрос к Mistral"""
        if not self.mistral_client:
            return None
        
        try:
            from mistralai import Mistral
            response = self.mistral_client.chat.complete(
                model=Config.MISTRAL_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=1000,
                top_p=0.9
            )

            if response and response.choices:
                return response.choices[0].message.content.strip()
            return None

        except Exception as e:
            print(f"Ошибка запроса к Mistral: {e}")
            return None
    
    def get_response(self, prompt):
        """Получение ответа от AI (Ollama -> Mistral)"""
        # Пробуем Ollama
        response = self.query_ollama(prompt)
        if response:
            return response
        
        # Пробуем Mistral
        if self.mistral_client:
            response = self.query_mistral(prompt)
            if response:
                return response
        
        return "Не удалось получить ответ от AI сервисов. Пожалуйста, попробуйте позже."


class PhoneValidator:
    @staticmethod
    def normalize_phone_number(phone):
        """Нормализация номера телефона"""
        if not phone:
            return None

        cleaned = re.sub(r'[^\d+]', '', phone)

        if not cleaned:
            return None

        if cleaned.startswith('8') and len(cleaned) == 11:
            return '+7' + cleaned[1:]
        elif cleaned.startswith('7') and len(cleaned) == 11:
            return '+' + cleaned
        elif cleaned.startswith('+7') and len(cleaned) == 12:
            return cleaned
        elif len(cleaned) == 10 and cleaned.isdigit():
            return '+7' + cleaned
        elif cleaned.startswith('+'):
            return cleaned

        return None


class UserInfoService:
    @staticmethod
    def get_user_info():
        """Получение информации о пользователе и времени"""
        try:
            from zoneinfo import ZoneInfo
            timezone = ZoneInfo("Europe/Moscow")
            now = datetime.now(timezone)
            current_time = now.strftime("%d %B %Y %H:%M MSK")
        except Exception:
            from datetime import timedelta
            now = datetime.utcnow() + timedelta(hours=3)
            current_time = now.strftime("%d %B %Y %H:%M MSK")

        return {
            "current_time": current_time,
            "country": "RU"
        }


# Инициализация сервисов
ai_assistant = AIAssistant()
phone_validator = PhoneValidator()
user_info_service = UserInfoService()

# Контекст процессоры
@app.context_processor
def inject_user_info():
    return user_info_service.get_user_info()

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

# Промпт для AI
def build_prompt(outcome):
    return f"""Ты ассистент банковского веб-приложения "ВТБ Онлайн-касса". 
Отвечай ТОЛЬКО на вопросы, связанные с банковскими операциями и функционалом приложения.
Если вопрос не о банке или деньгах, вежливо откажись отвечать.
Будь кратким (1-3 предложения).

Доступные функции:
- Регистрация и вход (/register, /login)
- Пополнение и снятие средств (/deposit, /withdraw)  
- Переводы по номеру телефона (/transfer)
- Просмотр профиля и истории операций (/profile)
- Курсы валют (/currency)
- Калькулятор вкладов (/deposit_calculator)

Вопрос пользователя: {outcome}

Ответ (кратко и по делу):"""

def sanitize_ai_text(text, max_len=4000):
    """Очистка текста от AI"""
    if not text:
        return ""

    text = text.replace('\r\n', '\n').replace('\r', '\n').strip()
    lines = text.split('\n')
    cleaned_lines = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if any(phrase in line.lower() for phrase in [
            'как эксперт', 'в качестве', 'проанализировав', 'рассмотрев вариант',
            'после анализа', 'исходя из', 'в заключение', 'таким образом',
            'в итоге', 'подводя итоги', 'в целом можно сказать'
        ]):
            continue
        cleaned_lines.append(line)

    cleaned = '\n'.join(cleaned_lines)
    cleaned = re.sub(r'^[\-\*\•\d\.]+\s*', '', cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r'[\*\-\•]', '', cleaned)

    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip() + '…'

    return cleaned

# Маршруты аутентификации
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
        phone_number = request.form["phone"].strip()
        password = request.form["password"]
        confirm_password = request.form.get("confirm_password", "")

        if password != confirm_password:
            return render_template("register.html", message="Пароли не совпадают")

        if len(password) < 4:
            return render_template("register.html", message="Пароль должен содержать не менее 4 символов")

        db = next(get_db())
        if db.query(User).filter_by(username=username).first():
            return render_template("register.html", message="Пользователь уже существует")

        normalized_phone = phone_validator.normalize_phone_number(phone_number)
        if not normalized_phone:
            return render_template("register.html", message="Неверный формат номера телефона")

        user = User(username=username, phone_number=normalized_phone)
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

# Маршруты профиля
@app.route("/profile")
@login_required
def profile():
    db = next(get_db())
    transactions = db.query(Transaction).filter_by(user_id=current_user.id).order_by(
        Transaction.timestamp.desc()).limit(10).all()

    return render_template("profile.html", 
                         user=current_user, 
                         transactions=transactions,
                         phone_number=current_user.phone_number)

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        username = request.form["username"].strip()
        phone_number = request.form["phone"].strip()
        current_password = request.form["current_password"]

        db = next(get_db())
        user = db.query(User).get(current_user.id)

        if not user.check_password(current_password):
            flash("Неверный текущий пароль", "danger")
            return redirect(url_for("edit_profile"))

        if username != user.username:
            existing_user = db.query(User).filter_by(username=username).first()
            if existing_user and existing_user.id != user.id:
                flash("Имя пользователя уже занято", "danger")
                return redirect(url_for("edit_profile"))
            user.username = username

        normalized_phone = phone_validator.normalize_phone_number(phone_number)
        if not normalized_phone:
            flash("Неверный формат номера телефона", "danger")
            return redirect(url_for("edit_profile"))

        if normalized_phone != user.phone_number:
            existing_phone = db.query(User).filter_by(phone_number=normalized_phone).first()
            if existing_phone and existing_phone.id != user.id:
                flash("Номер телефона уже используется", "danger")
                return redirect(url_for("edit_profile"))
            user.phone_number = normalized_phone

        try:
            db.commit()
            flash("Профиль успешно обновлен", "success")
            return redirect(url_for("profile"))
        except IntegrityError:
            db.rollback()
            flash("Ошибка при обновлении профиля", "danger")

    return render_template("edit_profile.html")

@app.route("/profile/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        db = next(get_db())
        user = db.query(User).get(current_user.id)

        if not user.check_password(current_password):
            flash("Неверный текущий пароль", "danger")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("Новые пароли не совпадают", "danger")
            return redirect(url_for("change_password"))

        if len(new_password) < 4:
            flash("Пароль должен содержать не менее 4 символов", "danger")
            return redirect(url_for("change_password"))

        user.set_password(new_password)

        try:
            db.commit()
            flash("Пароль успешно изменен", "success")
            return redirect(url_for("profile"))
        except Exception:
            db.rollback()
            flash("Ошибка при изменении пароля", "danger")

    return render_template("change_password.html")

# Маршруты операций
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
    current_user_db = db.query(User).get(current_user.id)
    user_balance = current_user_db.balance

    if request.method == "POST":
        try:
            target_phone = request.form["phone"].strip()
            amount = float(request.form["amount"])
            description = request.form.get("description", "").strip()

            normalized_phone = phone_validator.normalize_phone_number(target_phone)
            if not normalized_phone:
                flash("Неверный формат номера телефона", "danger")
                return render_template("transfer.html", user_balance=user_balance)

            target = db.query(User).filter_by(phone_number=normalized_phone).first()

            if not target:
                flash("Пользователь с таким номером телефона не найден", "danger")
            elif target.id == current_user.id:
                flash("Нельзя переводить средства самому себе", "danger")
            elif amount <= 0:
                flash("Сумма должна быть положительной", "danger")
            elif amount > user_balance:
                flash("Недостаточно средств на счету", "danger")
            else:
                sender = db.query(User).get(current_user.id)
                recipient = db.query(User).get(target.id)

                sender.balance -= amount
                recipient.balance += amount

                if not description:
                    out_description = f"Перевод {amount} ₽ → {recipient.username}"
                    in_description = f"Получено {amount} ₽ от {sender.username}"
                else:
                    out_description = f"Перевод {amount} ₽ → {recipient.username}: {description}"
                    in_description = f"Получено {amount} ₽ от {sender.username}: {description}"

                tx_out = Transaction(
                    user_id=sender.id,
                    type="transfer_out",
                    amount=amount,
                    target_id=recipient.id,
                    description=out_description
                )

                tx_in = Transaction(
                    user_id=recipient.id,
                    type="transfer_in",
                    amount=amount,
                    target_id=sender.id,
                    description=in_description
                )

                db.add_all([tx_out, tx_in])
                db.commit()

                flash(f"Успешно переведено {amount} ₽ пользователю {recipient.username}", "success")
                return redirect(url_for("profile"))

        except ValueError:
            flash("Некорректная сумма", "danger")
        except Exception as e:
            flash(f"Ошибка при выполнении перевода: {str(e)}", "danger")

    return render_template("transfer.html", user_balance=user_balance)

# API маршруты
@app.route("/api/find-user-by-phone", methods=["POST"])
@login_required
def find_user_by_phone():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    phone = data.get("phone", "").strip()
    if not phone:
        return jsonify({"error": "Номер телефона не указан"}), 400

    normalized_phone = phone_validator.normalize_phone_number(phone)
    if not normalized_phone:
        return jsonify({"error": "Неверный формат номера телефона"}), 400

    db = next(get_db())
    user = db.query(User).filter_by(phone_number=normalized_phone).first()

    if user:
        if user.id == current_user.id:
            return jsonify({"error": "Нельзя переводить самому себе"}), 400
        else:
            return jsonify({
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "phone_number": user.phone_number
                }
            })
    else:
        return jsonify({"error": "Пользователь не найден"}), 404

@app.route("/run-ai", methods=["POST"])
def run_ai():
    data = request.get_json() or {}
    outcomes = data.get("outcome", [])

    if isinstance(outcomes, list) and outcomes:
        outcome = outcomes[0]
    elif isinstance(outcomes, str):
        outcome = outcomes
    else:
        outcome = ""

    results = []

    if outcome:
        prompt = build_prompt(outcome)
        ai_text = ""

        try:
            ai_text_raw = ai_assistant.get_response(prompt)
            if ai_text_raw:
                ai_text = sanitize_ai_text(ai_text_raw)
            else:
                ai_text = "Не удалось получить ответ от AI сервисов."
        except Exception as e:
            print(f"AI error: {e}")
            ai_text = "Ошибка при получении ответа от AI."

        results.append({
            "outcome": outcome,
            "result": ai_text
        })

    return jsonify({"results": results}), 200

# Дополнительные маршруты
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
    user_info = user_info_service.get_user_info()
    return render_template('deposit_calculator.html',
                           current_time=user_info["current_time"],
                           country=user_info["country"])

# Инициализация тестовых данных
def init_test_data():
    db = SessionLocal()
    try:
        if not db.query(User).filter_by(username="admin").first():
            admin = User(username="admin", is_admin=True, balance=10000, phone_number="+72345678901")
            admin.set_password("admin123")
            
            alice = User(username="alice", balance=500, phone_number="+71234567890")
            alice.set_password("alice123")
            
            bob = User(username="bob", balance=300, phone_number="+78007006050")
            bob.set_password("bob123")
            
            db.add_all([admin, alice, bob])
            db.commit()
            print("Тестовые пользователи созданы")
        else:
            print("Тестовые пользователи уже существуют")
    except Exception as e:
        print(f"Ошибка при создании тестовых пользователей: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_test_data()
    app.run(port=5000, debug=True)
