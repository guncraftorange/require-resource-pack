import os
import shutil
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config

# 初始化 Flask 应用
app = Flask(__name__)
app.config.from_object(Config)

# 初始化 SQLAlchemy 和 LoginManager
db = SQLAlchemy()
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 保护路径管理
def get_protected_paths():
    if not os.path.exists(app.config['PROTECTED_PATHS_FILE']):
        return []
    with open(app.config['PROTECTED_PATHS_FILE'], 'r') as f:
        return [line.strip() for line in f.readlines()]

def manage_protected_path(action, path):
    protected = get_protected_paths()
    if action == 'add' and path not in protected:
        protected.append(path)
    elif action == 'remove' and path in protected:
        protected.remove(path)
    with open(app.config['PROTECTED_PATHS_FILE'], 'w') as f:
        f.write('\n'.join(protected))

# 文件浏览路由
@app.route('/')
def home():
    return redirect(url_for('browse'))

@app.route('/browse/')
@app.route('/browse/<path:subpath>')
def browse(subpath=''):
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], subpath)
    # 安全检查
    if not os.path.realpath(full_path).startswith(os.path.realpath(app.config['UPLOAD_FOLDER'])):
        abort(403)
    # 检查保护路径
    for protected in get_protected_paths():
        if subpath.startswith(protected) and not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
    if not os.path.exists(full_path):
        abort(404)
    if os.path.isfile(full_path):
        return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=True)
    items = []
    try:
        for name in os.listdir(full_path):
            item_path = os.path.join(subpath, name) if subpath else name
            abs_path = os.path.join(full_path, name)
            items.append({
                'name': name,
                'is_dir': os.path.isdir(abs_path),
                'path': item_path,
                'protected': any(item_path.startswith(p) for p in get_protected_paths())
            })
    except:
        abort(403)
    return render_template('browse.html', 
                         items=items,
                         current_path=subpath,
                         protected_paths=get_protected_paths())

# 文件上传路由
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        files = request.files.getlist('files[]')
        folder = request.form.get('folder', '')
        target_dir = os.path.join(app.config['UPLOAD_FOLDER'], folder)
        os.makedirs(target_dir, exist_ok=True)
        for file in files:
            if file.filename == '':
                continue
            filename = secure_filename(file.filename)
            file.save(os.path.join(target_dir, filename))
        flash('文件上传成功')
        return redirect(url_for('browse'))
    return render_template('upload.html')

# 用户认证路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('browse'))
        flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash('用户名已存在')
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        user = User(username=username, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
        flash('注册成功')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('browse'))

# 管理员路由
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        action = request.form.get('action')
        path = request.form.get('path')
        if action and path:
            manage_protected_path(action, path)
    return render_template('admin.html', 
                         protected_paths=get_protected_paths(),
                         current_path=request.args.get('path', ''))

# 在应用启动前完成数据库初始化
db.init_app(app)
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)