import os
import json
import stripe
import urllib.parse
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from email_validator import validate_email, EmailNotValidError
import google.generativeai as genai
from flask_mail import Mail, Message
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask_migrate import Migrate
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import MessageEvent, TextMessage, TextSendMessage

from models import db, User, CustomerData, QA, ConversationLog, ExampleQuestion
from config import DevelopmentConfig

def create_app(config_class=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    Migrate(app, db)

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
        knowledge_dict = { "data": {qa.question: qa.answer for qa in all_qas} }
        knowledge_dir = 'static/knowledge'
        os.makedirs(knowledge_dir, exist_ok=True)
        filepath = os.path.join(knowledge_dir, f"knowledge_{customer_data.user_id}.json")
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(knowledge_dict, f, ensure_ascii=False, indent=2)
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
        
    def professional_plan_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.customer_data.plan != 'professional':
                flash('この機能はプロフェッショナルプランでのみ利用可能です。', 'warning')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function

    def send_reset_email(user):
        token = user.get_reset_token()
        msg = Message('パスワード再設定リクエスト', sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
        msg.body = f'''パスワードを再設定するには、以下のリンクをクリックしてください (有効期限30分):
{url_for('reset_token', token=token, _external=True)}

もしこのリクエストに心当たりがない場合は、このメールを無視してください。
'''
        mail.send(msg)

    def send_confirmation_email(user):
        token = user.get_reset_token(expires_sec=86400)
        msg = Message('アカウントの有効化', sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
        msg.body = f'''アカウントを有効化するには、以下のリンクをクリックしてください:
{url_for('confirm_email', token=token, _external=True)}
'''
        mail.send(msg)
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated: return redirect(url_for('dashboard'))
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                if not user.confirmed:
                    flash('アカウントが有効化されていません。確認メールをご確認ください。', 'warning')
                    return redirect(url_for('login'))
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('メールアドレスまたはパスワードが正しくありません。', 'danger')
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated: return redirect(url_for('dashboard'))
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
            new_customer_data.trial_ends_at = datetime.utcnow() + timedelta(days=10)
            db.session.add(new_customer_data)
            db.session.commit()
            _regenerate_knowledge_file(new_customer_data)
            
            send_confirmation_email(new_user)
            flash('確認メールを送信しました。メールボックスを確認し、アカウントを有効化してください。', 'info')
            return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('ログアウトしました。', 'info')
        return redirect(url_for('login'))

    @app.route('/confirm/<token>')
    def confirm_email(token):
        user = User.verify_reset_token(token)
        if not user:
            flash('確認リンクが無効または期限切れです。', 'danger')
            return redirect(url_for('login'))
        if user.confirmed:
            flash('アカウントは既に有効化されています。ログインしてください。', 'info')
        else:
            user.confirmed = True
            user.confirmed_on = datetime.utcnow()
            db.session.commit()
            flash('アカウントが有効化されました！ログインしてください。', 'success')
        return redirect(url_for('login'))

    @app.route("/reset_password", methods=['GET', 'POST'])
    def reset_request():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            email = request.form.get('email')
            user = User.query.filter_by(email=email).first()
            if user:
                send_reset_email(user)
            flash('パスワード再設定用のメールを送信しました。メールボックスをご確認ください。', 'info')
            return redirect(url_for('login'))
        return render_template('reset_request.html')

    @app.route("/reset_password/<token>", methods=['GET', 'POST'])
    def reset_token(token):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        user = User.verify_reset_token(token)
        if user is None:
            flash('無効または期限切れのトークンです。', 'warning')
            return redirect(url_for('reset_request'))
        if request.method == 'POST':
            password = request.form.get('password')
            password2 = request.form.get('password2')
            if not password or len(password) < 8:
                flash('パスワードは8文字以上で設定してください。', 'danger')
                return render_template('reset_token.html', token=token)
            if password != password2:
                flash('パスワードが一致しません。', 'danger')
                return render_template('reset_token.html', token=token)
            
            user.set_password(password)
            db.session.commit()
            flash('パスワードが更新されました。ログインしてください。', 'success')
            return redirect(url_for('login'))
        return render_template('reset_token.html', token=token)

    @app.route('/dashboard')
    @login_required
    def dashboard():
        customer_data = current_user.customer_data
        if customer_data.plan == 'trial' and not customer_data.is_on_trial():
            flash('無料トライアルは終了しました。引き続きサービスをご利用いただくには、有料プランへのアップグレードが必要です。', 'warning')
        return render_template('dashboard.html', user=current_user, data=customer_data)

    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings():
        customer_data = current_user.customer_data
        if request.method == 'POST':
            customer_data.bot_name = request.form.get('bot_name', 'My Chatbot').strip()[:100]
            customer_data.welcome_message = request.form.get('welcome_message', 'こんにちは！').strip()[:500]
            customer_data.header_color = request.form.get('header_color', '#0ea5e9')
            customer_data.line_channel_token = request.form.get('line_channel_token', '').strip()
            customer_data.line_channel_secret = request.form.get('line_channel_secret', '').strip()
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
        customer_data = current_user.customer_data
        if customer_data.plan != 'professional':
            if customer_data.qas.count() >= 100:
                flash('無料プラン・トライアル中のQ&A登録上限数（100件）に達しました。', 'warning')
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
            abort(403)
        return redirect(url_for('qa_management'))

    @app.route('/logs')
    @login_required
    def conversation_logs():
        customer_data = current_user.customer_data
        if customer_data.plan != 'professional':
            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            logs = customer_data.logs.filter(ConversationLog.timestamp >= seven_days_ago).order_by(ConversationLog.timestamp.desc()).all()
        else:
            logs = customer_data.logs.order_by(ConversationLog.timestamp.desc()).all()
        return render_template('conversation_logs.html', logs=logs, user=current_user)

    @app.route('/example-questions')
    @login_required
    @professional_plan_required
    def manage_example_questions():
        questions = current_user.customer_data.example_questions.order_by(ExampleQuestion.id.asc()).all()
        return render_template('example_questions.html', example_questions=questions, user=current_user)

    @app.route('/example-questions/add', methods=['POST'])
    @login_required
    @professional_plan_required
    def add_example_question():
        text = request.form.get('text', '').strip()
        if current_user.customer_data.example_questions.count() >= 10:
            flash('質問例は最大10個まで登録できます。', 'warning')
            return redirect(url_for('manage_example_questions'))
        if text:
            new_eq = ExampleQuestion(text=text, customer_data=current_user.customer_data)
            db.session.add(new_eq)
            db.session.commit()
            flash('新しい質問例を追加しました。', 'success')
        return redirect(url_for('manage_example_questions'))

    @app.route('/example-questions/delete/<int:eq_id>', methods=['POST'])
    @login_required
    @professional_plan_required
    def delete_example_question(eq_id):
        eq_to_delete = ExampleQuestion.query.get_or_404(eq_id)
        if eq_to_delete.customer_data.user_id == current_user.id:
            db.session.delete(eq_to_delete)
            db.session.commit()
            flash('質問例を削除しました。', 'success')
        else:
            abort(403)
        return redirect(url_for('manage_example_questions'))

    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/terms')
    def terms_of_service():
        return render_template('terms.html')

    @app.route('/privacy')
    def privacy_policy():
        return render_template('privacy.html')

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
            msg = Message(subject=f"【LARUbot】お問い合わせ: {name}様", recipients=[recipient],
                          body=f"名前: {name}\nEmail: {email}\n\n{message_body}")
            mail.send(msg)
            return jsonify({'success': True, 'message': 'お問い合わせありがとうございます。'})
        except Exception as e:
            print(f"メール送信エラー: {e}")
            return jsonify({'success': False, 'message': 'メッセージ送信中にエラーが発生しました。'})

    @app.route('/create-checkout-session', methods=['POST'])
    @login_required
    def create_checkout_session():
        price_id = request.form.get('price_id')
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
            flash('決済ページの生成中にエラーが発生しました。', 'danger')
            return redirect(url_for('index'))

    @app.route('/stripe-webhook', methods=['POST'])
    def stripe_webhook():
        payload = request.data
        sig_header = request.headers.get('Stripe-Signature')
        webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        event = None
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        except (ValueError, stripe.error.SignatureVerificationError) as e:
            return 'Invalid payload', 400
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            customer_email = session.get('customer_email')
            user = User.query.filter_by(email=customer_email).first()
            if user:
                line_items = stripe.checkout.Session.list_line_items(session.id, limit=1)
                price_id = line_items.data[0].price.id
                plan_map = {
                    os.getenv('STRIPE_STARTER_PRICE_ID'): 'starter',
                    os.getenv('STRIPE_PRO_PRICE_ID'): 'professional',
                }
                user.customer_data.plan = plan_map.get(price_id, user.customer_data.plan)
                user.customer_data.stripe_customer_id = session.get('customer')
                db.session.commit()
        return 'Success', 200

    @app.route('/chatbot/<int:user_id>')
    def chatbot_page(user_id):
        customer_data = CustomerData.query.filter_by(user_id=user_id).first_or_404()
        example_questions = []
        if customer_data.plan == 'professional':
            example_questions = customer_data.example_questions.order_by(ExampleQuestion.id.asc()).all()
        return render_template('chatbot_page.html', data=customer_data, example_questions=example_questions)

    # --- ▼▼▼ ここからAI関連の関数を更新 ▼▼▼ ---
    def get_gemini_response(customer_data, user_message, session_id):
        # 1. ペルソナ（役割）設定
        bot_name = customer_data.bot_name or "アシスタント"
        system_prompt = f"""あなたは「{bot_name}」という名前の優秀なアシスタントです。
以下の制約条件とナレッジを厳密に守って、ユーザーの質問に回答してください。

# 制約条件
- 簡潔かつ丁寧に回答してください。
- ナレッジに含まれる情報だけで回答できる場合は、その情報を元に回答してください。
- ナレッジにない質問でも、一般的なことであればアシスタントとして回答してください。
- わからない場合は、無理に回答せず「申し訳ありませんが、わかりかねます」と正直に伝えてください。

# ナレッジ
"""

        # 2. ナレッジ（Q&Aデータ）の読み込みと活用
        knowledge_text = "（ナレッジはありません）"
        knowledge_filepath = os.path.join('static/knowledge', f"knowledge_{customer_data.user_id}.json")
        if os.path.exists(knowledge_filepath):
            try:
                with open(knowledge_filepath, 'r', encoding='utf-8') as f:
                    knowledge_data = json.load(f).get("data", {})
                    if knowledge_data:
                        knowledge_text = "\n".join([f"- Q: {q}\n  A: {a}" for q, a in knowledge_data.items()])
            except (IOError, json.JSONDecodeError) as e:
                print(f"ナレッジファイルの読み込みエラー: {e}")

        # 3. 会話履歴の取得と整形
        history = []
        try:
            # 直近5往復の会話を取得
            recent_logs = ConversationLog.query.filter_by(customer_data_id=customer_data.id, session_id=session_id)\
                                               .order_by(ConversationLog.timestamp.desc()).limit(5).all()
            recent_logs.reverse() # 時系列を昇順に戻す
            
            for log in recent_logs:
                history.append({'role': 'user', 'parts': [log.user_question]})
                if log.bot_answer:
                    history.append({'role': 'model', 'parts': [log.bot_answer]})
        except Exception as e:
            print(f"会話履歴の取得エラー: {e}")

        # 4. Gemini API呼び出し
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            full_prompt = system_prompt + knowledge_text
            
            chat_session = model.start_chat(history=[
                {'role': 'user', 'parts': [full_prompt]},
                {'role': 'model', 'parts': ["承知いたしました。ユーザーからの質問にお答えします。"]}
            ] + history)

            response = chat_session.send_message(user_message)
            return response.text, []

        except Exception as e:
            print(f"Gemini API Error: {e}")
            return "申し訳ありません、AIとの通信中にエラーが発生しました。", []

    @app.route('/ask/<int:user_id>', methods=['POST'])
    def ask_chatbot(user_id):
        customer_data = CustomerData.query.filter_by(user_id=user_id).first_or_404()
        user_message = request.json.get('message')
        session_id = request.json.get('session_id')

        if not user_message or not session_id:
            return jsonify({'answer': '不正なリクエストです。', "follow_up_questions": []})
        
        answer, follow_up_questions = get_gemini_response(customer_data, user_message, session_id)
        
        try:
            new_log = ConversationLog(
                user_question=user_message, 
                bot_answer=answer, 
                customer_data=customer_data, 
                session_id=session_id
            )
            db.session.add(new_log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"ログ保存エラー: {e}")

        return jsonify({"answer": answer, "follow_up_questions": follow_up_questions})
    
    # --- ▲▲▲ ここまでAI関連の関数を更新 ▲▲▲ ---

    @app.route("/line-webhook", methods=['POST'])
    def line_webhook():
        signature = request.headers['X-Line-Signature']
        body = request.get_data(as_text=True)
        all_customers = CustomerData.query.filter(CustomerData.line_channel_secret.isnot(None)).all()
        for customer in all_customers:
            handler = WebhookHandler(customer.line_channel_secret)
            try:
                # 本番環境ではhandleのままで良いが、複数ボットを捌くためparseを直接使う
                events = handler.parser.parse(body, signature)
                for event in events:
                    if isinstance(event, MessageEvent) and isinstance(event.message, TextMessage):
                        handle_message(event, customer)
                return 'OK'
            except InvalidSignatureError:
                # 署名が一致しない場合は次のカスタマーのシークレットで試す
                continue
        # どのカスタマーの署名とも一致しなかった場合
        abort(400)

    # --- ▼▼▼ LINE関連の関数を更新 ▼▼▼ ---
    def handle_message(event, customer_data):
        user_message = event.message.text
        line_bot_api = LineBotApi(customer_data.line_channel_token)
        session_id = event.source.user_id

        if customer_data.plan == 'trial' and not customer_data.is_on_trial():
            reply_text = "無料トライアルは終了しました。"
            line_bot_api.reply_message(event.reply_token, TextSendMessage(text=reply_text))
            return
        
        answer, _ = get_gemini_response(customer_data, user_message, session_id)
        
        try:
            new_log = ConversationLog(
                user_question=user_message, 
                bot_answer=answer, 
                customer_data=customer_data,
                session_id=session_id
            )
            db.session.add(new_log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"ログ保存エラー: {e}")
            
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text=answer))
    # --- ▲▲▲ LINE関連の関数を更新 ▲▲▲ ---

    @app.route('/admin')
    @login_required
    @admin_required
    def admin_dashboard():
        all_users = User.query.order_by(User.id.desc()).all()
        return render_template('admin_dashboard.html', user=current_user, all_users=all_users)
        
    return app

app = create_app()

@app.cli.command("make-admin")
def make_admin_command():
    email = input("管理者にしたいユーザーのメールアドレス: ")
    user = User.query.filter_by(email=email).first()
    if user:
        user.is_admin = True
        db.session.commit()
        print(f"Success: {email} is now an admin.")
    else:
        print(f"Error: User {email} not found.")

@app.cli.command("change-plan")
def change_plan_command():
    email = input("プラン変更したいユーザーのメールアドレス: ")
    user = User.query.filter_by(email=email).first()
    if user:
        print(f"Current plan for {email}: {user.customer_data.plan}")
        new_plan = input("New plan (trial, starter, professional): ")
        if new_plan in ['trial', 'starter', 'professional']:
            user.customer_data.plan = new_plan
            db.session.commit()
            print(f"Success: Plan for {email} changed to {new_plan}.")
        else:
            print("Invalid plan.")
    else:
        print(f"Error: User {email} not found.")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=True)