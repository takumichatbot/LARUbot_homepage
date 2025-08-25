from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    
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
    header_color = db.Column(db.String(7), default='#0ea5e9')
    plan = db.Column(db.String(50), default='free') 
    stripe_customer_id = db.Column(db.String(255), nullable=True)
    
    # ▼▼▼ トライアル終了日を保存する列を追加 ▼▼▼
    trial_ends_at = db.Column(db.DateTime, nullable=True)

    qas = db.relationship('QA', backref='customer_data', lazy='dynamic', cascade="all, delete-orphan")
    logs = db.relationship('ConversationLog', backref='customer_data', lazy='dynamic', cascade="all, delete-orphan")

    # ▼▼▼ トライアル状況を判定するヘルパー関数を追加 ▼▼▼
    def is_on_trial(self):
        """トライアル期間中かどうかを判定する"""
        return self.trial_ends_at and self.trial_ends_at > datetime.now(timezone.utc)

    def trial_days_remaining(self):
        """トライアルの残り日数を計算する"""
        if not self.is_on_trial():
            return 0
        delta = self.trial_ends_at - datetime.now(timezone.utc)
        return delta.days + 1
        
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