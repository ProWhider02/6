from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, roles_required, logout_user

app = Flask(__name__, template_folder='htmlxxd')
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rbac.db'
app.config['SECURITY_PASSWORD_SALT'] = 'some-random-salt'

db = SQLAlchemy(app)

roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean)
    fs_uniquifier = db.Column(db.String(64), unique=True, nullable=False)  # Нове поле
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.fs_uniquifier:
            import uuid
            self.fs_uniquifier = str(uuid.uuid4())

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
@roles_required('ROLE_ADMIN')
def admin():
    return render_template('admin.html')

@app.route('/user')
@roles_required('ROLE_USER')
def user():
    return render_template('user.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

def create_user():
    db.create_all()
    if not user_datastore.find_role('ROLE_ADMIN'):
        user_datastore.create_role(name='ROLE_ADMIN', description='Admin role')
    if not user_datastore.find_role('ROLE_USER'):
        user_datastore.create_role(name='ROLE_USER', description='User role')

    if not user_datastore.find_user(email='admin@example.com'):
        user_datastore.create_user(email='admin@example.com', password='password', roles=['ROLE_ADMIN'])
    if not user_datastore.find_user(email='user@example.com'):
        user_datastore.create_user(email='user@example.com', password='password', roles=['ROLE_USER'])

    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        create_user()
    app.run()
