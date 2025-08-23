import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """基本設定クラス"""
    # CSRF対策などで使われる秘密鍵。本番環境では必ず複雑な文字列を設定してください。
    SECRET_KEY = os.getenv('SECRET_KEY', 'a_very_long_and_random_secret_key')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = False
    TESTING = False

class DevelopmentConfig(Config):
    """開発環境用の設定"""
    DEBUG = True
    # 開発中はプロジェクト内にデータベースファイルを作成
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///development.db')

class ProductionConfig(Config):
    """本番環境用の設定"""
    # Renderなどの本番環境では、環境変数 'DATABASE_URL' を設定してください
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')