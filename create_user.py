from main import app, db, User, CustomerData

# ▼▼▼ あなたのログイン情報を設定してください ▼▼▼
# ログイン時に使用するメールアドレス
ADMIN_EMAIL = "larubotchatbot@gmail.com"  
# ログイン時に使用するパスワード（必ず推測されにくいものに変更してください）
ADMIN_PASSWORD = "LARUbot0713" 
# ▲▲▲ ここまで ▲▲▲

# Flaskアプリケーションのコンテキスト内でデータベース操作を実行
with app.app_context():
    # --- 1. データベースのテーブルを全て作成 ---
    print("データベースのテーブルを作成しています...")
    db.create_all()
    print("テーブルの作成が完了しました。")

    # --- 2. 既にユーザーが存在しないか確認 ---
    if User.query.filter_by(email=ADMIN_EMAIL).first():
        print(f"ユーザー '{ADMIN_EMAIL}' は既に存在します。")
    else:
        # --- 3. 新しい管理者ユーザーと、それに紐づく顧客データを作成 ---
        print(f"新しい管理者ユーザーを作成しています: {ADMIN_EMAIL}")
        
        # ユーザーを作成し、パスワードを安全にハッシュ化
        admin_user = User(email=ADMIN_EMAIL)
        admin_user.set_password(ADMIN_PASSWORD)
        
        # ユーザーに紐づく顧客データを作成（ボット名などはデフォルト値が使われます）
        customer_data_for_admin = CustomerData(user=admin_user)
        
        # データベースセッションに追加
        db.session.add(admin_user)
        db.session.add(customer_data_for_admin)
        
        # データベースに全ての変更を保存
        db.session.commit()
        
        print("管理者ユーザーと顧客データの作成が成功しました。")