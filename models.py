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
    plan = db.Column(db.String(50), default='trial') 
    stripe_customer_id = db.Column(db.String(255), nullable=True)
    
    trial_ends_at = db.Column(db.DateTime, nullable=True)

    qas = db.relationship('QA', backref='customer_data', lazy='dynamic', cascade="all, delete-orphan")
    logs = db.relationship('ConversationLog', backref='customer_data', lazy='dynamic', cascade="all, delete-orphan")

    def is_on_trial(self):
        """トライアル期間中かどうかを判定する"""
        return self.trial_ends_at and self.trial_ends_at > datetime.utcnow() # 'now(timezone.utc)' -> 'utcnow()' に修正済み

    def trial_days_remaining(self):
        """トライアルの残り日数を計算する"""
        if not self.is_on_trial():
            return 0
        # is_on_trialがutcnow()を使うので、ここも合わせてutcnow()を使用
        delta = self.trial_ends_at - datetime.utcnow()
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

class LineUser(db.Model):
    __tablename__ = 'line_user'
    id = db.Column(db.Integer, primary_key=True)
    # LINEから提供される一意のユーザーID
    line_user_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    # サービス内のUserモデルとの紐付け
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Userモデルとのリレーションシップを定義
    # これにより `line_user.user` のようにしてUserオブジェクトにアクセスできる
    user = db.relationship('User', backref=db.backref('line_user', uselist=False))

    def __repr__(self):
        return f'<LineUser {self.line_user_id}>'