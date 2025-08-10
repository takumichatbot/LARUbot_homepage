# main.py
from flask import Flask, render_template, request, jsonify
import os
from dotenv import load_dotenv
import google.generativeai as genai
from qa_data import QA_DATA
from flask_mail import Mail, Message

# 環境変数を読み込む
load_dotenv()

# Google APIキーが設定されているか確認
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY 環境変数が設定されていません。")
genai.configure(api_key=GOOGLE_API_KEY)

# Flaskアプリケーションの作成
app = Flask(__name__)

# ★★★ メール送信のための設定 ★★★
# Flask-Mailを使ってメールを送信するための設定をします
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# Mailオブジェクトを作成
mail = Mail(app)
# ★★★ ここまでメール送信設定 ★★★

# QAデータをプロンプトに組み込むためのテキストを作成
qa_prompt_text = "\n\n".join([f"### {key}\n{value}" for key, value in QA_DATA['data'].items()])

def get_gemini_answer(question):
    print(f"質問: {question}")
    try:
        model = genai.GenerativeModel('models/gemini-1.5-flash')
        print("Geminiモデルを初期化しました")

        # QA_DATAをプロンプトに組み込む
        full_question = f"""
        あなたはLARUbotのカスタマーサポートAIです。
        以下の「ルール・規則」セクションに記載されている情報のみに基づいて、お客様からの質問に絵文字を使わずに丁寧に回答してください。
        **記載されていない質問には「申し訳ありませんが、その情報はこのQ&Aには含まれていません。」と答えてください。**
        お客様がスムーズに手続きを進められるよう、元気で丁寧な言葉遣いで案内してください。
        
        ---
        ## ルール・規則
        {qa_prompt_text}
        ---

        お客様の質問: {question}
        """

        print("Gemini APIにリクエストを送信します...")
        response = model.generate_content(full_question, request_options={'timeout': 30})
        print("Gemini APIから応答を受け取りました")

        if response and response.text:
            return response.text.strip()
        else:
            print("APIから応答がありませんでした。")
            return "申し訳ありませんが、その質問にはお答えできませんでした。別の質問をしてください。"

    except Exception as e:
        print(f"Gemini APIエラー: {type(e).__name__} - {e}")
        return "申し訳ありませんが、現在AIが応答できません。しばらくしてから再度お試しください。"


@app.route('/')
def index():
    example_questions = QA_DATA.get('example_questions', [])
    return render_template('index.html', example_questions=example_questions)

@app.route('/ask', methods=['POST'])
def ask_chatbot():
    user_message = request.json.get('message')
    if not user_message:
        return jsonify({'answer': '質問が空です。'})

    bot_answer = get_gemini_answer(user_message)
    return jsonify({'answer': bot_answer})

# ★★★ お問い合わせフォームの送信エンドポイント ★★★
@app.route('/contact', methods=['POST'])
def contact():
    name = request.form.get('name')
    email = request.form.get('email')
    message = request.form.get('message')
    
    if not name or not email or not message:
        return jsonify({"success": False, "message": "すべての項目を入力してください。"})

    try:
        msg = Message(
            subject="【LARUbot_homepage】お問い合わせ",
            recipients=["larubotchatbot@gmail.com"],
            body=f"お名前: {name}\nメールアドレス: {email}\n\nお問い合わせ内容:\n{message}"
        )
        mail.send(msg)
        
        return jsonify({"success": True, "message": "お問い合わせを送信しました。"})

    except Exception as e:
        print(f"メール送信エラー: {e}")
        return jsonify({"success": False, "message": "メール送信に失敗しました。時間をおいて再度お試しください。"})
# ★★★ ここまでお問い合わせフォームの送信エンドポイント ★★★

if __name__ == '__main__':
    app.run(debug=True, port=5004)