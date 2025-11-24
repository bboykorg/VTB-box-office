import os
from os import environ
from datetime import datetime
import re
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from mistralai import Mistral
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.exc import IntegrityError
import requests

OLLAMA_URL = "http://localhost:11434"
#MODEL_NAME = "deepseek-r1:8b"
OLLAMA_MODEL_NAME = "gemma3:1b"

api_key = os.environ.get("MISTRAL_API_KEY")

if not api_key:
    raise RuntimeError("MISTRAL_API_KEY должен быть задан в окружении")

model = "mistral-tiny"

client = Mistral(api_key=api_key)

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
        timezone = ZoneInfo("Europe/Moscow")
        country = "RU"
        time_format = "%d %B %Y %H:%M MSK"
        now = datetime.now(timezone)
        current_time = now.strftime(time_format)

    except Exception:
        from datetime import timedelta
        offset_hours = 3
        country = "RU"
        time_format = "%d %B %Y %H:%M MSK"

        now = datetime.utcnow() + timedelta(hours=offset_hours)
        current_time = now.strftime(time_format)

    return {
        "current_time": current_time,
        "country": country
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
        username_or_phone = request.form["username"].strip()
        password = request.form["password"]
        db = next(get_db())

        user = db.query(User).filter(
            (User.username == username_or_phone) |
            (User.phone_number == normalize_phone_number(username_or_phone))
        ).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f"Добро пожаловать, {user.username}!", "success")
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

        user_info = get_user_info()
        registration_time = datetime.strptime(user_info["current_time"], "%d %B %Y %H:%M MSK")

        user = User(
            username=username,
            phone_number=phone_number,
            created_at=registration_time
        )
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
    return render_template("profile.html", user=current_user, transactions=transactions,
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

        normalized_phone = normalize_phone_number(phone_number)
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
            flash("Пароль успешно изменён", "success")
            return redirect(url_for("profile"))
        except Exception:
            db.rollback()
            flash("Ошибка при изменении пароля", "danger")

    return render_template("change_password.html")


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

                user_info = get_user_info()
                current_time = datetime.strptime(user_info["current_time"], "%d %B %Y %H:%M MSK")

                tx = Transaction(
                    user_id=user.id,
                    type="deposit",
                    amount=amount,
                    description=f"Внесение {amount}",
                    timestamp=current_time
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

                user_info = get_user_info()
                current_time = datetime.strptime(user_info["current_time"], "%d %B %Y %H:%M MSK")

                tx = Transaction(
                    user_id=user.id,
                    type="withdraw",
                    amount=amount,
                    description=f"Снятие {amount}",
                    timestamp=current_time
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

            normalized_phone = normalize_phone_number(target_phone)
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
                flash("Недостаточно средств на счету. Пожалуйста, пополните счет.", "danger")
            else:
                sender = db.query(User).get(current_user.id)
                recipient = db.query(User).get(target.id)

                sender.balance -= amount
                recipient.balance += amount

                user_info = get_user_info()
                current_time = datetime.strptime(user_info["current_time"], "%d %B %Y %H:%M MSK")

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
                    description=out_description,
                    timestamp=current_time
                )

                tx_in = Transaction(
                    user_id=recipient.id,
                    type="transfer_in",
                    amount=amount,
                    target_id=sender.id,
                    description=in_description,
                    timestamp=current_time
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

def normalize_phone_number(phone):
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


@app.route("/api/find-user-by-phone", methods=["POST"])
@login_required
def find_user_by_phone():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    phone = data.get("phone", "").strip()

    if not phone:
        return jsonify({"error": "Номер телефона не указан"}), 400

    normalized_phone = normalize_phone_number(phone)
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

@app.route("/execute-transfer", methods=["POST"])
@login_required
def execute_transfer():
    if request.method == "POST":
        try:
            recipient_id = request.form.get("recipient_id")
            amount = float(request.form.get("amount"))
            description = request.form.get("description", "")
            password = request.form.get("password")

            if not current_user.check_password(password):
                flash("Неверный пароль", "danger")
                return redirect(url_for("transfer"))

            db = next(get_db())
            recipient = db.query(User).get(recipient_id)
            sender = db.query(User).get(current_user.id)

            if not recipient:
                flash("Получатель не найден", "danger")
                return redirect(url_for("transfer"))

            if amount > sender.balance:
                flash("Недостаточно средств", "danger")
                return redirect(url_for("transfer"))

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

        except Exception as e:
            flash(f"Ошибка при выполнении перевода: {str(e)}", "danger")
            return redirect(url_for("transfer"))

    return redirect(url_for("transfer"))


@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash("Доступ запрещён", "danger")
        return redirect(url_for("profile"))
    db = next(get_db())
    transactions = db.query(Transaction).order_by(Transaction.timestamp.desc()).all()
    users = db.query(User).all()
    user_info = get_user_info()
    return render_template("admin.html", transactions=transactions, users=users)

@app.route('/deposit_calculator')
def deposit_calculator():
    user_info = get_user_info()
    return render_template('deposit_calculator.html')


def build_prompt(outcome):
    prompt = ("""Ты ассистент банковского веб-приложения "ВТБ Онлайн-касса". 
Твоя задача - помогать пользователям ориентироваться в функциях приложения.

ПОЛНАЯ СТРУКТУРА ПРИЛОЖЕНИЯ:

1. СИСТЕМА АУТЕНТИФИКАЦИИ:
   - Регистрация (/register):
     * Обязательные поля: имя пользователя, номер телефона, пароль
     * Номер телефона должен быть в формате: +79991234567, 89991234567 или 9991234567
     * Пароль минимум 4 символа
     * Проверка уникальности имени пользователя и номера телефона

   - Вход (/login): по имени пользователя ИЛИ номеру телефона и паролю
   - Выход (/logout)

2. ГЛАВНАЯ СТРАНИЦА (/):
   - Навигационное меню со всеми доступными функциями
   - Доступна только после авторизации

3. ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ (/profile):
   - Отображение текущего баланса
   - Показ номера телефона пользователя
   - История последних 10 транзакций с датами и описаниями
   - Информация о дате регистрации

4. ОПЕРАЦИИ СО СЧЕТОМ:
   - Пополнение счета (/deposit):
     * Ввод суммы для пополнения
     * Сумма должна быть положительной
     * Баланс увеличивается на указанную сумму
     * Создается запись в истории транзакций типа "deposit"

   - Снятие средств (/withdraw):
     * Ввод суммы для снятия
     * Проверка достаточности средств
     * Сумма должна быть положительной и не превышать баланс
     * Баланс уменьшается на указанную сумму
     * Создается запись в истории транзакций типа "withdraw"

5. СИСТЕМА ПЕРЕВОДОВ (/transfer):
   - Переводы осуществляются ТОЛЬКО по номеру телефона
   - Поддерживаемые форматы номеров:
     * Международный: +79991234567
     * Российский с 8: 89991234567  
     * Без кода страны: 9991234567
   - Система автоматически нормализует номер телефона
   - Поиск получателя в реальном времени при вводе номера
   - Валидация: нельзя переводить самому себе
   - Проверка достаточности средств перед переводом
   - Создание двух записей в транзакциях:
     * У отправителя: тип "transfer_out" 
     * У получателя: тип "transfer_in"
   - Возможность добавить описание к переводу

6. ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ:
   - Курсы валют (/currency) - страница для просмотра актуальных курсов
   - Калькулятор вкладов (/deposit_calculator) - расчет доходности вкладов

7. АДМИНИСТРАТИВНАЯ ПАНЕЛЬ (/admin):
   - Доступна только пользователям с флагом is_admin=True
   - Просмотр всех пользователей системы
   - Просмотр всех транзакций всех пользователей
   - Сортировка транзакций по дате (новые сверху)

8. БАЗА ДАННЫХ И МОДЕЛИ:

   Модель User:
   - id: идентификатор пользователя
   - username: уникальное имя пользователя
   - phone_number: уникальный номер телефона
   - password_hash: хеш пароля
   - balance: текущий баланс счета
   - is_admin: флаг администратора
   - created_at: дата регистрации

   Модель Transaction:
   - id: идентификатор транзакции
   - user_id: ссылка на пользователя
   - type: тип операции (deposit, withdraw, transfer_out, transfer_in)
   - amount: сумма операции
   - target_id: для переводов - ID получателя/отправителя
   - timestamp: дата и время операции
   - description: описание операции

9. ТЕСТОВЫЕ ПОЛЬЗОВАТЕЛИ (создаются автоматически):
   - admin / admin123:
     * Баланс: 10,000 ₽
     * Номер телефона: +72345678901
     * Права: администратор

   - alice / alice123:
     * Баланс: 500 ₽
     * Номер телефона: +71234567890

   - bob / bob123:
     * Баланс: 300 ₽
     * Номер телефона: +78007006050

10. ТЕХНИЧЕСКИЕ ОСОБЕННОСТИ:
    - Фреймворк: Flask
    - База данных: SQLite (файл VTB.db)
    - ORM: SQLAlchemy
    - Аутентификация: Flask-Login
    - Интерфейс: Bootstrap 5
    - Порт приложения: 5000

11. ВАЖНЫЕ ОГРАНИЧЕНИЯ И ОСОБЕННОСТИ:
    - Нет функции оплаты счетов или QR-кодов
    - Нет кредитов, ипотек или рассрочек
    - Нет мобильного приложения, только веб-версия
    - Нет уведомлений по email или SMS
    - Нет истории транзакций старше 10 операций в профиле
    - Нет восстановления пароля
    - Нет смены номера телефона после регистрации
    - Нет мультивалютных счетов
    - Нет привязки банковских карт

12. ПРОЦЕСС ПЕРЕВОДА:
    1. Пользователь вводит номер телефона получателя
    2. Система проверяет формат и нормализует номер
    3. Осуществляется поиск пользователя по номеру
    4. Если пользователь найден, отображается его имя
    5. Пользователь вводит сумму перевода
    6. Система проверяет достаточность средств
    7. При подтверждении создаются две транзакции

13. СИСТЕМА БЕЗОПАСНОСТИ:
    - Пароли хранятся в хешированном виде (Werkzeug)
    - Сессии управляются через Flask-Login
    - CSRF-защита через Flask-WTF (если используется)
    - Валидация всех входящих данных

14. API ЭНДПОИНТЫ:
    - /api/find-user-by-phone (POST): поиск пользователя по номеру телефона
    - /run-ai (POST): AI-ассистент для ответов на вопросы

ИНСТРУКЦИЯ ДЛЯ ОТВЕТОВ:
- Отвечай ТОЛЬКО на вопросы, связанные с описанным функционалом
- Если вопрос не о банковском приложении или не о деньгах впринципе, вежливо откажись отвечать
- Объясняй функции конкретно и по шагам
- Указывай точные пути URL (/profile, /transfer и т.д.)
- Не придумывай несуществующие функции
- Сообщения должны быть краткими (1-3 предложения)
- При переводе всегда упоминай, что нужен номер телефона получателя

Вопрос пользователя: {outcome}

Ответ (кратко и по делу):""").format(outcome=outcome)
    return prompt


def sanitize_ai_text(text, max_len=4000):
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
            'как эксперт', 'в качестве', 'проанализировав',
            'рассмотрев вариант', 'после анализа', 'исходя из'
        ]):
            continue

        if any(phrase in line.lower() for phrase in [
            'в заключение', 'таким образом', 'в итоге',
            'подводя итоги', 'в целом можно сказать'
        ]):
            continue

        cleaned_lines.append(line)

    cleaned = '\n'.join(cleaned_lines)
    cleaned = re.sub(r'^[\-\*\•\d\.]+\s*', '', cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r'[\*\-\•]', '', cleaned)

    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip() + '…'

    return cleaned


def query_ollama(prompt):
    try:
        payload = {
            "model": OLLAMA_MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "top_k": 40,
            }
        }

        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            return result.get("response", "").strip()
        else:
            print(f"Ошибка Ollama: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.ConnectionError:
        print("Не удалось подключиться к Ollama. Убедитесь, что Ollama запущен.")
        return None
    except requests.exceptions.Timeout:
        print("Таймаут при запросе к Ollama.")
        return None
    except Exception as e:
        print(f"Неожиданная ошибка при запросе к Ollama: {e}")
        return None


def query_mistral(prompt):
    try:
        response = client.chat.complete(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.7,
            max_tokens=1000,
            top_p=0.9
        )

        if response and response.choices:
            return response.choices[0].message.content.strip()
        else:
            print("Пустой ответ от Mistral")
            return None

    except Exception as e:
        print(f"Ошибка при запросе к Mistral: {e}")
        return None


def get_ai_response(prompt):
    """Основная функция для получения ответа от AI — сначала Ollama, затем Mistral"""

    print("Попытка подключения к Ollama...")
    response = query_ollama(prompt)

    if response:
        print("Успешно получен ответ от Ollama")
        return response

    print("Ollama не доступен, пробуем Mistral...")
    response = query_mistral(prompt)

    if response:
        print("Успешно получен ответ от Mistral")
        return response

    print("Оба AI сервиса не доступны")
    return "Не удалось получить ответ от AI сервисов. Пожалуйста, попробуйте позже."



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
            ai_text_raw = get_ai_response(prompt)

            if ai_text_raw:
                ai_text = sanitize_ai_text(ai_text_raw)
                print(f"[run-ai] succeeded for outcome: {outcome}")
            else:
                ai_text = "Не удалось получить ответ от AI сервисов."
                print(f"[run-ai] failed for outcome: {outcome}")

        except Exception as e:
            print(f"[run-ai] error for outcome {outcome}: {e}")
            ai_text = "Ошибка при получении ответа от AI. Попробуйте позже."

        results.append({
            "outcome": outcome,
            "result": ai_text
        })

    return jsonify({"results": results}), 200


with app.app_context():
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
    app.run(port=5001, debug=True)