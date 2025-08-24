import os
import json
import re
import stripe
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from email_validator import validate_email, EmailNotValidError
import google.generativeai as genai
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from functools import wraps

from models import db, User, CustomerData, QA, ConversationLog
from config import DevelopmentConfig

def create_app(config_class=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'このページにアクセスするにはログインが必要です。'
    login_manager.login_message_category = 'info'

    stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
    mail = Mail(app)

    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    if GOOGLE_API_KEY:
        genai.configure(api_key=GOOGLE_API_KEY)
    else:
        print("警告: .envファイルにGOOGLE_API_KEYが見つかりません。AI機能は無効になります。")

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def _regenerate_knowledge_file(customer_data):
        all_qas = customer_data.qas.all()
        example_questions = [qa.question for qa in all_qas[:5]]
        knowledge_dict = {
            "data": {qa.question: qa.answer for qa in all_qas},
            "example_questions": example_questions
        }
        knowledge_dir = 'static/knowledge'
        os.makedirs(knowledge_dir, exist_ok=True)
        filepath = os.path.join(knowledge_dir, f"knowledge_{customer_data.user_id}.json")
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(knowledge_dict, f, ensure_ascii=False, indent=2)
            print(f"ナレッジファイルを更新しました: {filepath}")
        except IOError as e:
            print(f"ナレッジファイルの書き込みエラー: {e}")

    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.is_admin:
                flash('このページにアクセスする権限がありません。', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function

    # --- 認証ルート ---
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('メールアドレスまたはパスワードが正しくありません。', 'danger')
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            password2 = request.form.get('password2')
            try:
                validate_email(email)
                if User.query.filter_by(email=email).first():
                    flash('このメールアドレスは既に使用されています。', 'danger')
                    return redirect(url_for('register'))
            except EmailNotValidError:
                flash('有効なメールアドレスを入力してください。', 'danger')
                return redirect(url_for('register'))
            if not password or len(password) < 8:
                flash('パスワードは8文字以上で設定してください。', 'danger')
                return redirect(url_for('register'))
            if password != password2:
                flash('パスワードが一致しません。', 'danger')
                return redirect(url_for('register'))
            new_user = User(email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            new_customer_data = CustomerData(user_id=new_user.id)
            db.session.add(new_customer_data)
            db.session.commit()
            _regenerate_knowledge_file(new_customer_data)
            flash('アカウント登録が完了しました。ログインしてください。', 'success')
            return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('ログアウトしました。', 'info')
        return redirect(url_for('login'))

    # --- ダッシュボード関連のルート ---
    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html', user=current_user, data=current_user.customer_data)

    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings():
        customer_data = current_user.customer_data
        if request.method == 'POST':
            customer_data.bot_name = request.form.get('bot_name', 'My Chatbot').strip()[:100]
            customer_data.welcome_message = request.form.get('welcome_message', 'こんにちは！').strip()[:500]
            customer_data.header_color = request.form.get('header_color', '#0ea5e9')
            db.session.commit()
            flash('設定を保存しました！', 'success')
            return redirect(url_for('settings'))
        return render_template('settings.html', data=customer_data, user=current_user)

    @app.route('/qa')
    @login_required
    def qa_management():
        qas = current_user.customer_data.qas.order_by(QA.id.desc()).all()
        return render_template('qa_management.html', qas=qas, user=current_user)

    @app.route('/qa/add', methods=['POST'])
    @login_required
    def add_qa():
        customer_plan = current_user.customer_data.plan
        if customer_plan == 'starter' and current_user.customer_data.qas.count() >= 100:
            flash('Q&Aの登録上限数（100件）に達しました。無制限に登録するには、プロフェッショナルプランへのアップグレードをご検討ください。', 'warning')
            return redirect(url_for('qa_management'))
        question = request.form.get('question', '').strip()
        answer = request.form.get('answer', '').strip()
        if question and answer:
            new_qa = QA(question=question, answer=answer, customer_data=current_user.customer_data)
            db.session.add(new_qa)
            db.session.commit()
            _regenerate_knowledge_file(current_user.customer_data)
            flash('新しいQ&Aを追加しました。', 'success')
        else:
            flash('質問と回答の両方を入力してください。', 'danger')
        return redirect(url_for('qa_management'))

    @app.route('/qa/delete/<int:qa_id>', methods=['POST'])
    @login_required
    def delete_qa(qa_id):
        qa_to_delete = QA.query.get_or_404(qa_id)
        if qa_to_delete.customer_data.user_id == current_user.id:
            db.session.delete(qa_to_delete)
            db.session.commit()
            _regenerate_knowledge_file(current_user.customer_data)
            flash('Q&Aを削除しました。', 'success')
        else:
            flash('このQ&Aを削除する権限がありません。', 'danger')
        return redirect(url_for('qa_management'))

    @app.route('/logs')
    @login_required
    def conversation_logs():
        customer_plan = current_user.customer_data.plan
        if customer_plan == 'starter':
            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            logs = current_user.customer_data.logs.filter(ConversationLog.timestamp >= seven_days_ago).order_by(ConversationLog.timestamp.desc()).all()
        else:
            logs = current_user.customer_data.logs.order_by(ConversationLog.timestamp.desc()).all()
        return render_template('conversation_logs.html', logs=logs, user=current_user)

    # --- 公開ページとAPIのルート ---
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/contact', methods=['POST'])
    def contact():
        name = request.form.get('name')
        email = request.form.get('email')
        message_body = request.form.get('message')
        if not all([name, email, message_body]):
            return jsonify({'success': False, 'message': '全てのフィールドを入力してください。'})
        recipient = app.config['MAIL_USERNAME']
        if not recipient:
            print("メールエラー: .envにMAIL_USERNAMEが設定されていません。")
            return jsonify({'success': False, 'message': 'サーバー側でエラーが発生しました。'})
        try:
            msg = Message(
                subject=f"【LARUbot】ウェブサイトからのお問い合わせ: {name}様",
                recipients=[recipient],
                body=f"お名前: {name}\nメールアドレス: {email}\n\nお問い合わせ内容:\n{message_body}"
            )
            mail.send(msg)
            return jsonify({'success': True, 'message': 'お問い合わせありがとうございます。内容を確認し、折り返しご連絡いたします。'})
        except Exception as e:
            print(f"メール送信エラー: {e}")
            return jsonify({'success': False, 'message': 'メッセージの送信中にエラーが発生しました。'})

    # --- Stripe決済用のルート ---
    @app.route('/create-checkout-session', methods=['POST'])
    @login_required
    def create_checkout_session():
        price_id = request.form.get('price_id')
        if not price_id:
            flash('価格情報が選択されていません。', 'danger')
            return redirect(url_for('index'))
        try:
            checkout_session = stripe.checkout.Session.create(
                line_items=[{'price': price_id, 'quantity': 1}],
                mode='subscription',
                success_url=url_for('dashboard', _external=True) + '?payment=success',
                cancel_url=url_for('index', _external=True) + '?payment=cancel',
                customer_email=current_user.email,
            )
            return redirect(checkout_session.url, code=303)
        except Exception as e:
            print(f"Stripe エラー: {e}")
            flash('決済ページの生成中にエラーが発生しました。サポートにお問い合わせください。', 'danger')
            return redirect(url_for('index'))

    # --- Stripe Webhook用のルート ---
    @app.route('/stripe-webhook', methods=['POST'])
    def stripe_webhook():
        payload = request.data
        sig_header = request.headers.get('Stripe-Signature')
        webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        if not webhook_secret:
            print("Stripe Webhookシークレットが設定されていません。")
            return 'Webhook secret not configured', 500
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
        except ValueError as e:
            print(f"Webhook ValueError: {e}")
            return 'Invalid payload', 400
        except stripe.error.SignatureVerificationError as e:
            print(f"Webhook SignatureVerificationError: {e}")
            return 'Invalid signature', 400
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            customer_email = session.get('customer_email')
            stripe_customer_id = session.get('customer')
            user = User.query.filter_by(email=customer_email).first()
            if user:
                try:
                    line_items = stripe.checkout.Session.list_line_items(session.id, limit=1)
                    price_id = line_items.data[0].price.id
                    if price_id == os.getenv('STRIPE_STARTER_PRICE_ID'):
                        user.customer_data.plan = 'starter'
                    elif price_id == os.getenv('STRIPE_PRO_PRICE_ID'):
                        user.customer_data.plan = 'professional'
                    user.customer_data.stripe_customer_id = stripe_customer_id
                    db.session.commit()
                    print(f"成功: ユーザー {customer_email} のプランを {user.customer_data.plan} に更新しました。")
                except Exception as e:
                    print(f"データベース更新中にエラーが発生しました: {e}")
        return 'Success', 200

    # --- チャットボットAPIと公開ページ ---
    @app.route('/chatbot/<int:user_id>')
    def chatbot_page(user_id):
        customer_data = CustomerData.query.filter_by(user_id=user_id).first_or_404()
        example_questions = []
        if customer_data.plan == 'professional':
            knowledge_file = os.path.join('static/knowledge', f"knowledge_{customer_data.user_id}.json")
            if os.path.exists(knowledge_file):
                try:
                    with open(knowledge_file, 'r', encoding='utf-8') as f:
                        knowledge = json.load(f)
                        example_questions = knowledge.get('example_questions', [])
                except (IOError, json.JSONDecodeError) as e:
                    print(f"ナレッジファイルの読み込みエラー: {e}")
        return render_template('chatbot_page.html', data=customer_data, example_questions=example_questions)

    @app.route('/ask/<int:user_id>', methods=['POST'])
    def ask_chatbot(user_id):
        customer_data = CustomerData.query.filter_by(user_id=user_id).first_or_404()
        knowledge_file = os.path.join('static/knowledge', f"knowledge_{user_id}.json")
        if not os.path.exists(knowledge_file):
            return jsonify({"answer": "設定ファイルが見つかりません。", "follow_up_questions": []})
        try:
            with open(knowledge_file, 'r', encoding='utf-8') as f:
                knowledge = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"ナレッジファイルの読み込みエラー: {e}")
            return jsonify({"answer": "設定ファイルの読み込み中にエラーが発生しました。", "follow_up_questions": []})
        user_message = request.json.get('message')
        if not user_message:
            return jsonify({'answer': '質問が空です。', "follow_up_questions": []})
        qa_prompt_text = "\n\n".join([f"### {key}\n{value}" for key, value in knowledge.get('data', {}).items()])
        model = genai.GenerativeModel('models/gemini-1.5-flash')
        prompt_data = {
            "system_role": "あなたはLARUbotの優秀なカスタマーサポートAIです。以下のナレッジベースに記載されている情報をすべて注意深く読み、お客様の質問に対する答えを探してください。答えがナレッジベース内に明確に記載されている場合は、その情報のみを使って丁寧に回答してください。複数の項目に関連する可能性がある場合は、それらを統合して答えてください。**もし、いくら探しても答えがナレッジベース内に見つからない場合のみ、「申し訳ありませんが、その情報はこのQ&Aには含まれていません。」と答えてください。**",
            "follow_up_prompt": "あなたはユーザーの思考を先読みするアシスタントです。上記の会話と、あなたが回答の根拠として使用したナレッジベース全体を考慮して、ユーザーが次に関心を持ちそうな質問を3つ提案してください。**提案する質問は、必ずナレッジベース内の情報から回答できるものにしてください。** 回答は必ずJSON形式の文字列リスト（例: [\"質問1\", \"質問2\", \"質問3\"]）で、リスト以外の文字列は一切含めずに返してください。適切な質問がなければ空のリスト `[]` を返してください。",
            "not_found": "申し訳ありませんが、その情報はこのQ&Aには含まれていません。",
            "error": "申し訳ありませんが、現在AIが応答できません。しばらくしてから再度お試しください。"
        }
        answer = ""
        follow_up_questions = []
        try:
            full_question = f"{prompt_data['system_role']}\n\n---\n## ナレッジベース\n{qa_prompt_text}\n---\n\nお客様の質問: {user_message}"
            response = model.generate_content(full_question, request_options={'timeout': 30})
            answer = response.text.strip() if response and response.text else prompt_data['not_found']
        except Exception as e:
            print(f"Gemini APIエラー (回答生成): {e}")
            answer = prompt_data['error']
        if "申し訳ありません" not in answer:
            try:
                follow_up_request = f"## ナレッジベース\n{qa_prompt_text}\n\n## 直前の会話\nユーザーの質問: {user_message}\nAIの回答: {answer}\n\n## 指示\n{prompt_data['follow_up_prompt']}"
                follow_up_response = model.generate_content(follow_up_request, request_options={'timeout': 20})
                json_str_match = re.search(r'\[.*\]', follow_up_response.text, re.DOTALL)
                follow_up_questions = json.loads(json_str_match.group()) if json_str_match else []
            except Exception as e:
                print(f"Gemini APIエラー (関連質問生成): {e}")
        try:
            new_log = ConversationLog(user_question=user_message, bot_answer=answer, customer_data=customer_data)
            db.session.add(new_log)
            db.session.commit()
        except Exception as e:
            print(f"ログ保存エラー: {e}")
            db.session.rollback()
        return jsonify({"answer": answer, "follow_up_questions": follow_up_questions})

    # --- 管理者用ダッシュボードのルート ---
    @app.route('/admin')
    @login_required
    @admin_required
    def admin_dashboard():
        all_users = User.query.order_by(User.id.desc()).all()
        return render_template('admin_dashboard.html', user=current_user, all_users=all_users)

    return app

# --- アプリケーションの実行 ---
# ▼▼▼【修正点】コマンド登録をifブロックの外に移動 ▼▼▼
app = create_app()

@app.cli.command("reset-db")
def reset_db_command():
    """データベースをリセット（全テーブルを削除して再作成）する"""
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("データベースを正常にリセットしました。")

@app.cli.command("init-db")
def init_db_command():
    """データベースを初期化（テーブルを作成）する"""
    with app.app_context():
        db.create_all()
    print("データベースを初期化しました。")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)