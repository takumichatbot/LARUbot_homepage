from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # index=True を追加すると、メールアドレスでの検索が高速になります
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    
    # リレーションシップ
    customer_data = db.relationship('CustomerData', backref='user', uselist=False, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CustomerData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    bot_name = db.Column(db.String(100), default='My Chatbot')
    welcome_message = db.Column(db.String(500), default='こんにちは！何かご質問はありますか？')
    # ホームページのテーマカラーに合わせてデフォルト値を変更
    header_color = db.Column(db.String(7), default='#0ea5e9')
    
    # リレーションシップ
    qas = db.relationship('QA', backref='customer_data', lazy='dynamic', cascade="all, delete-orphan")
    logs = db.relationship('ConversationLog', backref='customer_data', lazy='dynamic', cascade="all, delete-orphan")

class QA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    answer = db.Column(db.Text, nullable=False)
    customer_data_id = db.Column(db.Integer, db.ForeignKey('customer_data.id'), nullable=False)

class ConversationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_question = db.Column(db.Text, nullable=False)
    bot_answer = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    customer_data_id = db.Column(db.Integer, db.ForeignKey('customer_data.id'), nullable=False)