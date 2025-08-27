from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from flask import current_app
from itsdangerous import URLSafeTimedSerializer as Serializer

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    
    confirmed = db.Column(db.Boolean, nullable=False, default=False, server_default='f')
    confirmed_on = db.Column(db.DateTime, nullable=True)

    customer_data = db.relationship('CustomerData', backref='user', uselist=False, cascade="all, delete-orphan")

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=1800)
            user_id = data.get('user_id')
        except:
            return None
        return User.query.get(user_id)

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
    line_channel_token = db.Column(db.String(255), nullable=True)
    line_channel_secret = db.Column(db.String(255), nullable=True)
    onboarding_completed = db.Column(db.Boolean, nullable=False, default=False)
    enable_weekly_report = db.Column(db.Boolean, nullable=False, default=True)
    report_day_of_week = db.Column(db.Integer, nullable=False, default=1)

    # ▼▼▼ 以下の1行を新しく追加します ▼▼▼
    uncertain_reply = db.Column(db.String(500), nullable=False, default='申し訳ありませんが、わかりかねます。')
    # ▲▲▲ ここまで追加 ▲▲▲

    qas = db.relationship('QA', backref='customer_data', lazy='dynamic', cascade="all, delete-orphan")
    logs = db.relationship('ConversationLog', backref='customer_data', lazy='dynamic', cascade="all, delete-orphan")
    example_questions = db.relationship('ExampleQuestion', backref='customer_data', lazy='dynamic', cascade="all, delete-orphan")
    menu_items = db.relationship('MenuItem', backref='customer_data', lazy=True, cascade="all, delete-orphan")

    def is_on_trial(self):
        return self.trial_ends_at and self.trial_ends_at > datetime.utcnow()

    def trial_days_remaining(self):
        if not self.is_on_trial():
            return 0
        delta = self.trial_ends_at - datetime.utcnow()
        return delta.days + 1

class QA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    answer = db.Column(db.Text, nullable=False)
    customer_data_id = db.Column(db.Integer, db.ForeignKey('customer_data.id'), nullable=False)

class ConversationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), nullable=False, index=True)
    user_question = db.Column(db.Text, nullable=False)
    bot_answer = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    customer_data_id = db.Column(db.Integer, db.ForeignKey('customer_data.id'), nullable=False)

class ExampleQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    customer_data_id = db.Column(db.Integer, db.ForeignKey('customer_data.id'), nullable=False)

    def __repr__(self):
        return f'<ExampleQuestion {self.text}>'

class LineUser(db.Model):
    __tablename__ = 'line_user'
    id = db.Column(db.Integer, primary_key=True)
    line_user_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('line_user', uselist=False))

    def __repr__(self):
        return f'<LineUser {self.line_user_id}>'

class MenuItem(db.Model):
    """カルーセルメニュー項目を保存するためのモデル"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    image_url = db.Column(db.String(500), nullable=True)
    action_text = db.Column(db.String(50), nullable=False, default='これにする')
    customer_data_id = db.Column(db.Integer, db.ForeignKey('customer_data.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<MenuItem {self.title}>'