from __future__ import annotations

import os
import re
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional

from flask import (
    Flask, request, render_template, session, flash,
    redirect, url_for, send_from_directory, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import UniqueConstraint, event, Index
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import Engine
from werkzeug.middleware.proxy_fix import ProxyFix

# =============================================================================
# App & Config
# =============================================================================

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.config.update(
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///nebulainteligence.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.getenv("SECRET_KEY", secrets.token_urlsafe(32)),
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"

# =============================================================================
# DB
# =============================================================================

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()
    except Exception:
        pass

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    senha = db.Column(db.String(255), nullable=False)
    maquinas_criadas = db.Column(db.Integer, default=0, nullable=False)

    maquinas = db.relationship(
        "Maquinas",
        backref="dono",
        lazy=True,
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_users_email_unique", "email", unique=True),
    )

class Maquinas(db.Model):
    __tablename__ = "maquinas"
    id = db.Column(db.Integer, primary_key=True)
    maquina_nome = db.Column(db.String(150), nullable=False)
    maquina_senha = db.Column(db.String(255), nullable=False)  # hash
    maquina_dono_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    codigo = db.Column(db.String(6), nullable=False, unique=True, index=True)

    __table_args__ = (
        UniqueConstraint("maquina_dono_id", "maquina_nome", name="uq_dono_nome"),
        Index("ix_maquinas_codigo_unique", "codigo", unique=True),
    )

with app.app_context():
    db.create_all()

# =============================================================================
# Helpers
# =============================================================================

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

def _cap(text: str, limit: int) -> str:
    text = text or ""
    return text[:limit]

def sanitize_name(s: str, *, limit: int = 150) -> str:
    s = _cap(s.strip(), limit)
    return re.sub(r"[^A-Za-z0-9 _\-\.]", "", s)

def strong_code() -> str:
    return "".join(secrets.choice(string.digits) for _ in range(6))

def gerar_codigo_unico(max_tentativas: int = 40) -> str:
    for _ in range(max_tentativas):
        cod = strong_code()
        if not Maquinas.query.filter_by(codigo=cod).first():
            return cod
    raise RuntimeError("Não foi possível gerar código único.")

def _user_downloads_dir(uid: Optional[int] = None) -> str:
    uid = uid or (current_user.id if current_user.is_authenticated else None)
    if uid is None:
        raise RuntimeError("Usuário não autenticado.")
    base = os.path.realpath(os.path.join("user", str(uid), "downloads"))
    os.makedirs(base, exist_ok=True)
    return base

def _safe_user_path(relative_path: str) -> str:
    base = _user_downloads_dir()
    alvo = os.path.realpath(os.path.join(base, relative_path))
    if not (alvo == base or alvo.startswith(base + os.sep)):
        raise ValueError("Caminho inválido.")
    return alvo

def enviar_email(codigo: str, destinatario: str) -> str:
    # Fallback simples: imprime no console para desenvolvimento
    print(f"[FALLBACK EMAIL] Para: {destinatario} | Código: {codigo}")
    return "FALLBACK_PRINTED"

@login_manager.user_loader
def load_user(user_id: str):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# =============================================================================
# Rotas principais
# =============================================================================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/inicio")
@login_required
def inicio():
    maquinas = Maquinas.query.filter_by(maquina_dono_id=current_user.id).all()
    return render_template("inicio.html", maquinas=maquinas)
@app.route('/admin')
def admin():
    return render_template("adminpaineil.html")
@app.route("/entrar_maquina/<int:maquina_id>", methods=["GET", "POST"])
@login_required
def entrar_maquina(maquina_id: int):
    maquina = Maquinas.query.filter_by(
        id=maquina_id, maquina_dono_id=current_user.id
    ).first()
    if not maquina:
        flash("Máquina não encontrada ou não pertence a você.", "error")
        return redirect(url_for("inicio"))

    if request.method == "POST":
        senha = _cap((request.form.get("senha") or "").strip(), 255)
        if check_password_hash(maquina.maquina_senha, senha):
            session["codigo_maquina_atual"] = maquina.codigo
            flash(f"Você entrou na máquina {maquina.maquina_nome}.", "success")
            return redirect(url_for("area_de_trabalho"))
        else:
            flash("Senha incorreta para esta máquina.", "error")
            return redirect(url_for("entrar_maquina", maquina_id=maquina.id))

    # GET → exibe tela de login da máquina
    return render_template("user.html", maquina=maquina)

@app.route("/area_de_trabalho")
@login_required
def area_de_trabalho():
    codigo2 = session.get("codigo_maquina_atual", "")
    if not codigo2:
        flash("Nenhuma máquina selecionada.", "error")
        return redirect(url_for("inicio"))

    maquina = Maquinas.query.filter_by(
        codigo=codigo2, maquina_dono_id=current_user.id
    ).first()
    if not maquina:
        flash("Máquina inválida ou não pertence a você.", "error")
        return redirect(url_for("inicio"))

    return render_template("area_de_trabalho.html", maquina=maquina)

# =============================================================================
# File Manager
# =============================================================================

@app.route("/files")
@login_required
def files():
    user_dir = _user_downloads_dir()
    arquivos = []
    for nome in os.listdir(user_dir):
        if nome.startswith("."):
            continue
        caminho = os.path.join(user_dir, nome)
        if os.path.isdir(caminho):
            tipo = "Pasta"
            tamanho = None
        else:
            tipo = "Arquivo"
            try:
                tamanho = os.path.getsize(caminho)
            except OSError:
                tamanho = None
        arquivos.append({"nome": nome, "tipo": tipo, "tamanho": tamanho})
    return render_template("files.html", arquivos=arquivos)

@app.route("/abrir_arquivo", methods=["POST"])
@login_required
def abrir_arquivo():
    data = request.get_json(force=True, silent=True) or {}
    nome = sanitize_name(data.get("caminho") or "", limit=255)
    if not nome:
        return jsonify({"erro": "Caminho não informado!"}), 400
    try:
        caminho = _safe_user_path(nome)
    except ValueError:
        return jsonify({"erro": "Caminho inválido!"}), 400
    if not os.path.exists(caminho) or os.path.isdir(caminho):
        return jsonify({"erro": "Arquivo inválido!"}), 400
    with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
        conteudo = f.read()
    return jsonify({"conteudo": conteudo})

@app.route("/salvar_arquivo", methods=["POST"])
@login_required
def salvar_arquivo():
    data = request.get_json(force=True, silent=True) or {}
    nome = sanitize_name(data.get("caminho") or "", limit=255)
    conteudo = data.get("conteudo", "")
    if not nome:
        return jsonify({"erro": "Caminho não informado!"}), 400
    try:
        caminho = _safe_user_path(nome)
    except ValueError:
        return jsonify({"erro": "Caminho inválido!"}), 400
    if not os.path.exists(caminho) or os.path.isdir(caminho):
        return jsonify({"erro": "Arquivo inválido!"}), 400
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(conteudo)
    return jsonify({"status": "ok"})

@app.route("/user/<int:user_id>/downloads/<path:filename>")
@login_required
def baixar_arquivo(user_id: int, filename: str):
    if current_user.id != user_id:
        flash("Acesso negado!", "error")
        return redirect(url_for("files"))
    user_dir = _user_downloads_dir(user_id)
    filename = os.path.basename(filename)
    return send_from_directory(user_dir, filename, as_attachment=True)

# =============================================================================
# Registro / Verificação / Login
# =============================================================================

@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nome = sanitize_name(request.form.get("nome") or "", limit=100)
        email = _cap((request.form.get("email") or "").strip().lower(), 255)
        senha = request.form.get("senha") or ""
        confirmar = request.form.get("confirmar_senha") or ""

        if not nome or not email or not senha or not confirmar:
            flash("Preencha todos os campos.", "error")
            return redirect(url_for("registro"))
        if not EMAIL_RE.match(email):
            flash("E-mail inválido.", "error")
            return redirect(url_for("registro"))
        if senha != confirmar:
            flash("As senhas não coincidem.", "error")
            return redirect(url_for("registro"))
        if len(senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "error")
            return redirect(url_for("registro"))
        if User.query.filter_by(email=email).first():
            flash("Email já cadastrado.", "error")
            return redirect(url_for("registro"))

        codigo = strong_code()
        session["temp_user"] = {
            "nome": nome,
            "email": email,
            "senha": generate_password_hash(senha),
            "codigo": codigo,
            "expira_em": (datetime.utcnow() + timedelta(minutes=10)).isoformat(),
        }
        r = enviar_email(codigo, email)
        if r == "FALLBACK_PRINTED":
            flash("Código gerado e impresso no console.", "success")
        elif r == "SENT":
            flash(f"Código enviado para {email}.", "success")
        else:
            flash("Erro ao enviar email.", "error")
            session.pop("temp_user", None)
            return redirect(url_for("registro"))
        return redirect(url_for("verified"))

    return render_template("registro.html")

@app.route("/verified", methods=["GET", "POST"])
def verified():
    if request.method == "POST":
        temp = session.get("temp_user")
        if not temp:
            flash("Sessão expirada.", "error")
            return redirect(url_for("registro"))
        if datetime.utcnow() > datetime.fromisoformat(temp["expira_em"]):
            flash("O código expirou.", "error")
            session.pop("temp_user", None)
            return redirect(url_for("registro"))
        if _cap((request.form.get("codigo") or "").strip(), 6) != temp["codigo"]:
            flash("Código inválido.", "error")
            return redirect(url_for("verified"))
        try:
            novo = User(nome=temp["nome"], email=temp["email"], senha=temp["senha"])
            db.session.add(novo)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Este e-mail já foi usado.", "error")
            return redirect(url_for("login"))
        os.makedirs(_user_downloads_dir(novo.id), exist_ok=True)
        session.pop("temp_user", None)
        flash("Conta verificada! Faça login.", "success")
        return redirect(url_for("login"))
    return render_template("verified.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = _cap((request.form.get("email") or "").strip().lower(), 255)
        senha = request.form.get("senha") or ""
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.senha, senha):
            login_user(user)
            flash("Login realizado!", "success")
            return redirect(url_for("inicio"))
        flash("Email ou senha inválidos.", "error")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("codigo_maquina_atual", None)
    flash("Você saiu da conta.", "success")
    return redirect(url_for("login"))

# =============================================================================
# Gerenciar Máquinas
# =============================================================================

@app.route("/new_maquina")
@login_required
def new_maquina():
    return render_template("newMaquina.html")

@app.route("/criar_maquina", methods=["POST"])
@login_required
def maquina_db():
    maquina = sanitize_name(request.form.get("maquina") or "", limit=150)
    senha = _cap((request.form.get("senha") or ""), 255)

    if not maquina or not senha:
        flash("Preencha nome e senha.", "error")
        return redirect(url_for("new_maquina"))
    if len(maquina) < 3:
        flash("Nome muito curto.", "error")
        return redirect(url_for("new_maquina"))
    if len(senha) < 8:
        flash("Senha muito curta.", "error")
        return redirect(url_for("new_maquina"))

    codigo2 = gerar_codigo_unico()

    try:
        nova = Maquinas(
            maquina_nome=maquina,
            maquina_senha=generate_password_hash(senha),
            maquina_dono_id=current_user.id,
            codigo=codigo2,
        )
        db.session.add(nova)
        db.session.flush()
        current_user.maquinas_criadas = (current_user.maquinas_criadas or 0) + 1
        db.session.commit()
        flash("Máquina criada!", "success")
        return redirect(url_for("inicio"))
    except IntegrityError as e:
        db.session.rollback()
        if "uq_dono_nome" in str(e.orig):
            flash("Você já tem uma máquina com esse nome.", "error")
        else:
            flash("Conflito de código, tente novamente.", "error")
        return redirect(url_for("inicio"))

@app.route("/minhas_maquinas")
@login_required
def minhas_maquinas():
    maquinas = Maquinas.query.filter_by(maquina_dono_id=current_user.id).all()
    return render_template("minhasMaquinas.html", maquinas=maquinas)

@app.route("/deletar_maquina/<int:maquina_id>", methods=["POST"])
@login_required
def deletar_maquina(maquina_id: int):
    maq = Maquinas.query.filter_by(id=maquina_id, maquina_dono_id=current_user.id).first()
    if not maq:
        flash("Máquina não encontrada.", "error")
        return redirect(url_for("minhas_maquinas"))
    db.session.delete(maq)
    db.session.commit()
    if session.get("codigo_maquina_atual") == maq.codigo:
        session.pop("codigo_maquina_atual", None)
    flash("Máquina deletada.", "success")
    return redirect(url_for("minhas_maquinas"))

# =============================================================================
# Run
# =============================================================================

if __name__ == "__main__":
    os.makedirs("user", exist_ok=True)
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os, secrets, string

# ==========================================================
# App e Config
# ==========================================================
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nebulainteligence.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ==========================================================
# Models
# ==========================================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    senha = db.Column(db.String(255), nullable=False)
    maquinas_criadas = db.Column(db.Integer, default=0, nullable=False)
    maquinas = db.relationship("Maquina", backref="dono", lazy=True, cascade="all, delete-orphan")

class Maquina(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    maquina_nome = db.Column(db.String(150), nullable=False)
    maquina_senha = db.Column(db.String(255), nullable=False)
    maquina_dono_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    codigo = db.Column(db.String(6), unique=True, nullable=False)

# Cria o DB
with app.app_context():
    db.create_all()
    os.makedirs("user", exist_ok=True)

# ==========================================================
# Helpers
# ==========================================================
def gerar_codigo_unico():
    while True:
        cod = ''.join(secrets.choice(string.digits) for _ in range(6))
        if not Maquina.query.filter_by(codigo=cod).first():
            return cod

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================================
# Rotas - Autenticação
# ==========================================================
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        confirmar = request.form.get('confirmar_senha')

        if not nome or not email or not senha or not confirmar:
            flash("Preencha todos os campos.", "error")
            return redirect(url_for('registro'))
        if senha != confirmar:
            flash("As senhas não coincidem.", "error")
            return redirect(url_for('registro'))
        if len(senha) < 8:
            flash("A senha deve ter ao menos 8 caracteres.", "error")
            return redirect(url_for('registro'))
        if User.query.filter_by(email=email).first():
            flash("Email já cadastrado.", "error")
            return redirect(url_for('registro'))

        novo = User(nome=nome, email=email, senha=generate_password_hash(senha))
        db.session.add(novo)
        db.session.commit()
        flash("Conta criada! Faça login.", "success")
        return redirect(url_for('login'))
    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('senha')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.senha, senha):
            login_user(user)
            flash("Login realizado!", "success")
            return redirect(url_for('new_maquina'))
        flash("Email ou senha inválidos.", "error")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('codigo_maquina_atual', None)
    flash("Você saiu da conta.", "success")
    return redirect(url_for('login'))

# ==========================================================
# Rotas - Máquinas
# ==========================================================
@app.route('/new_maquina')
@login_required
def new_maquina():
    return render_template('newMaquina.html')

@app.route('/criar_maquina', methods=['POST'])
@login_required
def criar_maquina():
    nome = request.form.get('maquina')
    senha = request.form.get('senha')

    if not nome or len(nome)<3:
        flash("Nome muito curto.", "error")
        return redirect(url_for('new_maquina'))
    if not senha or len(senha)<8:
        flash("Senha muito curta.", "error")
        return redirect(url_for('new_maquina'))

    codigo = gerar_codigo_unico()
    nova = Maquina(maquina_nome=nome, maquina_senha=generate_password_hash(senha),
                   maquina_dono_id=current_user.id, codigo=codigo)
    db.session.add(nova)
    current_user.maquinas_criadas += 1
    db.session.commit()
    flash("Máquina criada com sucesso!", "success")
    return redirect(url_for('new_maquina'))

@app.route('/minhas_maquinas')
@login_required
def minhas_maquinas():
    maquinas = Maquina.query.filter_by(maquina_dono_id=current_user.id).all()
    return render_template('minhasMaquinas.html', maquinas=maquinas)

@app.route('/deletar_maquina/<int:maquina_id>', methods=['POST'])
@login_required
def deletar_maquina(maquina_id):
    maq = Maquina.query.filter_by(id=maquina_id, maquina_dono_id=current_user.id).first()
    if not maq:
        flash("Máquina não encontrada.", "error")
        return redirect(url_for('minhas_maquinas'))
    db.session.delete(maq)
    db.session.commit()
    if session.get('codigo_maquina_atual') == maq.codigo:
        session.pop('codigo_maquina_atual', None)
    flash("Máquina deletada.", "success")
    return redirect(url_for('minhas_maquinas'))

# ==========================================================
# Run
# ==========================================================
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)

