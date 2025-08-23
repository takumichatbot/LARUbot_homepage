// DOMが読み込まれたら処理を開始
document.addEventListener('DOMContentLoaded', function () {
    // 必要なHTML要素を取得
    const messagesContainer = document.getElementById('chatbot-messages');
    const userInput = document.getElementById('user-input');
    const sendButton = document.getElementById('send-button');
    const exampleButtons = document.querySelectorAll('.example-btn');

    // 送信ボタンがクリックされたらsendMessage関数を呼び出す
    sendButton.addEventListener('click', sendMessage);

    // 入力欄でEnterキーが押されたらsendMessage関数を呼び出す
    userInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
    
    // 質問例ボタンがクリックされたときの処理
    exampleButtons.forEach(button => {
        button.addEventListener('click', () => {
            // ボタンのテキストを入力欄に入れて、メッセージを送信
            userInput.value = button.textContent;
            sendMessage();
            
            // 質問例のコンテナを削除してスッキリさせる
            const initialExamples = document.getElementById('initial-example-questions');
            if (initialExamples) {
                initialExamples.remove();
            }
        });
    });

    // メッセージを送信するメインの関数
    function sendMessage() {
        const messageText = userInput.value.trim();
        if (messageText === '') return; // 空のメッセージは送信しない

        // ユーザーのメッセージを画面に表示
        appendMessage(messageText, 'user-message');
        userInput.value = ''; // 入力欄を空にする

        // タイピングインジケーターを表示
        showTypingIndicator();

        // サーバー（API）にユーザーのメッセージを送信
        fetch(API_ENDPOINT, { // API_ENDPOINTはHTML側で定義されています
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: messageText }),
        })
        .then(response => response.json())
        .then(data => {
            // サーバーから返信が来たら
            removeTypingIndicator(); // タイピングインジケーターを削除
            appendMessage(data.answer, 'bot-message'); // ボットの返信を画面に表示
        })
        .catch(error => {
            // エラーが発生した場合
            console.error('API Error:', error);
            removeTypingIndicator();
            appendMessage('申し訳ありません、エラーが発生しました。', 'bot-message');
        });
    }

    // 新しいメッセージをチャット画面に追加する関数
    function appendMessage(text, className) {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', className);
        messageDiv.textContent = text;
        messagesContainer.appendChild(messageDiv);
        // 自動で一番下までスクロールする
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // 「...」というタイピングインジケーターを表示する関数
    function showTypingIndicator() {
        const typingDiv = document.createElement('div');
        typingDiv.id = 'typing-indicator';
        typingDiv.classList.add('message', 'bot-message');
        typingDiv.innerHTML = `
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
        `;
        messagesContainer.appendChild(typingDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // タイピングインジケーターを削除する関数
    function removeTypingIndicator() {
        const typingIndicator = document.getElementById('typing-indicator');
        if (typingIndicator) {
            typingIndicator.remove();
        }
    }
});