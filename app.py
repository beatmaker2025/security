# secure_app.py — 安全注册+登录+数据库+JWT 全套版 🔐
from flask import Flask, request, make_response, jsonify, abort, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv
import jwt
import datetime
import os
import logging

# ===== 加载 .env 文件 =====
load_dotenv()

# ===== Flask 配置 =====
app = Flask(__name__)
app.secret_key = os.getenv("JWT_SECRET", "default-secret")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True

# ===== 初始化扩展 =====
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
app.wsgi_app = ProxyFix(app.wsgi_app)

# ===== 安全头 =====
csp = {
    'default-src': "'self'",
    'script-src': ["'self'"],
    'style-src': ["'self'", 'https://fonts.googleapis.com'],
    'font-src': ["'self'", 'https://fonts.gstatic.com'],
    'img-src': ["'self'", 'data:']
}
Talisman(app, content_security_policy=csp, force_https=True)

# ===== 限速配置 =====
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/hour"],
    storage_uri=os.getenv('REDIS_URL', 'memory://')
)
limiter.init_app(app)

# ===== 日志 =====
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

# ===== 用户模型 =====
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

# ===== 表单 =====
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

# ===== 初始化数据库 =====
with app.app_context():
    db.create_all()

# ===== 注册 =====
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            return "用戶已存在", 400
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login_page'))
    return render_template('register.html', form=form)

# ===== 登录 API 返回 JWT =====
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    if user and user.verify_password(data.get('password')):
        payload = {
            'user': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }
        token = jwt.encode(payload, app.secret_key, algorithm='HS256')
        return jsonify({'token': token})
    else:
        abort(401, description='登入失敗')

# ===== 登入頁面 + 表單表現 =====
@app.route('/login-page', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data):
            session['user'] = user.username
            return redirect(url_for('dashboard'))
        else:
            return "登入失敗", 401
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html', username=session['user'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/protected')
def protected():
    token = request.headers.get('Authorization')
    if not token:
        abort(401, description='未提供 token')
    try:
        decoded = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return f"歡迎使用者 {decoded['user']}，你已通過驗證"
    except jwt.ExpiredSignatureError:
        abort(401, description='Token 已過期')
    except jwt.InvalidTokenError:
        abort(401, description='Token 無效')

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    return jsonify(error="Internal Server Error"), 500

@app.after_request
def remove_server_header(response):
    response.headers['Server'] = ''
    response.headers['X-Powered-By'] = ''
    return response

if __name__ == '__main__':
    app.run(debug=True)
