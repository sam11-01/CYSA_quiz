# CEH_Quiz — 跨電腦進度同步功能

說明：
本專案在不破壞既有功能下，加入「跨電腦繼續做題」功能。實作重點：

1. 採雙重儲存機制：
   - 前端：使用 localStorage 保留離線/即時進度（不影響既有邏輯）。
   - 後端：提供 REST API 將進度存入伺服器（SQLite），並以 `user_token` 作為識別（可匿名或註冊）以達成跨電腦同步。

2. 使用者識別策略：
   - 預設（最簡易、立即可用）流程：首次使用時前端產生一個隨機 `user_token`（UUID），儲存在 localStorage，並顯示一組可複製/匯入的「同步代碼」。使用者在另一台電腦貼上該代碼即可載入同樣的進度。此方式不需帳密即可跨電腦。
   - 進階（選用）：提供簡單 Email + 密碼 註冊/登入（JWT）來綁定進度（本範例以選用方式註記）。

3. API 設計（簡潔）：
   - `POST /api/progress/save`  接收 `{ user_token, quiz_id, progress_json }`；回傳 success。
   - `GET  /api/progress/load?user_token=...&quiz_id=...` 回傳該 user_token 的 progress。
   - `POST /api/user/claim` 用於把匿名 token 升級（例如綁定 email），此為選用。

4. 相容性與可插拔性：
   - 後端以 Flask + SQLAlchemy 實作，使用 SQLite 方便部署與開發。API 與資料表設計簡潔，應可在既有專案中以最小改動整合。
   - 前端只需新增一個 `save_progress.js` 並在主要頁面載入，並在頁面 `unload`、做題每題答題後，呼叫 `saveProgressToServer()`。

5. 上傳的原始專案：請先將上傳的壓縮檔解壓到專案根目錄，路徑：
```
/mnt/data/CEH_Quiz.zip
```
(解壓後請依說明把 backend 資料夾與 frontend 新增檔案合併到原專案。)

---

## 檔案樹（本說明提供必要檔案）
```
CEH_Quiz/
├─ backend/
│  ├─ requirements.txt
│  ├─ app.py
│  ├─ models.py
│  ├─ db_init.py
│  └─ README_BACKEND.md
├─ frontend/
│  ├─ save_progress.js
│  ├─ progress_ui.html (範例同步代碼 UI)
│  └─ README_FRONTEND.md
└─ README.md
```

---

## 1) backend/requirements.txt
```
Flask==2.2.5
SQLAlchemy==1.4.50
Flask-Cors==3.0.10
python-dotenv==1.0.0
uuid==1.30
```

---

## 2) backend/models.py
```python
from sqlalchemy import Column, Integer, String, Text, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class Progress(Base):
    __tablename__ = 'progress'
    id = Column(Integer, primary_key=True)
    user_token = Column(String(128), index=True, nullable=False)
    quiz_id = Column(String(128), index=True, nullable=False)
    progress_json = Column(Text, nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    def to_dict(self):
        return {
            'id': self.id,
            'user_token': self.user_token,
            'quiz_id': self.quiz_id,
            'progress_json': self.progress_json,
            'updated_at': str(self.updated_at)
        }
```

---

## 3) backend/db_init.py
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base

def init_db(db_path='sqlite:///ceh_quiz.db'):
    engine = create_engine(db_path, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return engine

if __name__ == '__main__':
    init_db()
    print('DB initialized')
```

---

## 4) backend/app.py
```python
from flask import Flask, request, jsonify
from flask_cors import CORS
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Progress, Base
import os
import uuid

DB_PATH = os.getenv('CEH_DB', 'sqlite:///ceh_quiz.db')

app = Flask(__name__)
CORS(app)

engine = create_engine(DB_PATH, connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

@app.route('/api/progress/save', methods=['POST'])
def save_progress():
    data = request.get_json() or {}
    user_token = data.get('user_token')
    quiz_id = data.get('quiz_id')
    progress_json = data.get('progress_json')

    if not user_token or not quiz_id or progress_json is None:
        return jsonify({'success': False, 'error': 'missing fields'}), 400

    session = Session()
    # 若已有紀錄，覆寫；否則建立
    existing = session.query(Progress).filter_by(user_token=user_token, quiz_id=quiz_id).first()
    if existing:
        existing.progress_json = progress_json
    else:
        p = Progress(user_token=user_token, quiz_id=quiz_id, progress_json=progress_json)
        session.add(p)
    session.commit()
    session.close()
    return jsonify({'success': True})

@app.route('/api/progress/load', methods=['GET'])
def load_progress():
    user_token = request.args.get('user_token')
    quiz_id = request.args.get('quiz_id')
    if not user_token or not quiz_id:
        return jsonify({'success': False, 'error': 'missing params'}), 400
    session = Session()
    existing = session.query(Progress).filter_by(user_token=user_token, quiz_id=quiz_id).first()
    if not existing:
        session.close()
        return jsonify({'success': True, 'progress': None})
    result = existing.to_dict()
    session.close()
    return jsonify({'success': True, 'progress': result})

@app.route('/api/user/new_token', methods=['POST'])
def new_token():
    # 前端可用此 API 產生匿名 token（也可由前端直接產生）
    t = str(uuid.uuid4())
    return jsonify({'success': True, 'user_token': t})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

---

## 5) frontend/save_progress.js
```javascript
/*
  前端儲存/載入進度：
  - 會自動在 localStorage 建立 user_token (若不存在)
  - 提供公開函式 saveProgressToServer(quizId, progressObject)
  - 提供載入函式 loadProgressFromServer(quizId)
  - 提供匯出/匯入 token 的 UI helper
*/

(function(window){
  const API_BASE = (window.CEH_API_BASE || '').replace(/\/$/, '') || 'http://localhost:5000/api'
  const TOKEN_KEY = 'ceh_quiz_user_token'

  function ensureToken(){
    let t = localStorage.getItem(TOKEN_KEY)
    if(!t){
      t = crypto.randomUUID ? crypto.randomUUID() : ('tok-' + Math.random().toString(36).slice(2))
      localStorage.setItem(TOKEN_KEY, t)
    }
    return t
  }

  async function saveProgressToServer(quizId, progressObject){
    const user_token = ensureToken()
    const payload = {
      user_token,
      quiz_id: quizId,
      progress_json: JSON.stringify(progressObject)
    }
    // 同時保存在 localStorage
    localStorage.setItem(`progress_${quizId}_${user_token}`, JSON.stringify(progressObject))

    try{
      const r = await fetch(`${API_BASE}/progress/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      return await r.json()
    }catch(e){
      console.warn('儲存進度到伺服器失敗，保留於 localStorage', e)
      return { success: false, error: e.message }
    }
  }

  async function loadProgressFromServer(quizId){
    const user_token = ensureToken()
    // 先嘗試 localStorage
    const localKey = `progress_${quizId}_${user_token}`
    const local = localStorage.getItem(localKey)
    if(local){
      try{ return { success: true, progress: JSON.parse(local) } }
      catch(e){}
    }

    try{
      const url = new URL(`${API_BASE}/progress/load`)
      url.searchParams.append('user_token', user_token)
      url.searchParams.append('quiz_id', quizId)
      const r = await fetch(url.toString())
      const j = await r.json()
      if(j.success && j.progress && j.progress.progress_json){
        const parsed = JSON.parse(j.progress.progress_json)
        // 存回 localStorage
        localStorage.setItem(localKey, JSON.stringify(parsed))
        return { success: true, progress: parsed }
      }
      return { success: true, progress: null }
    }catch(e){
      console.warn('載入進度失敗', e)
      return { success: false, error: e.message }
    }
  }

  function exportToken(){
    const t = ensureToken()
    return t
  }

  function importToken(token){
    if(!token) return false
    localStorage.setItem(TOKEN_KEY, token)
    return true
  }

  // 將函式掛到全域以方便整合舊專案
  window.CEH = window.CEH || {}
  window.CEH.saveProgressToServer = saveProgressToServer
  window.CEH.loadProgressFromServer = loadProgressFromServer
  window.CEH.exportToken = exportToken
  window.CEH.importToken = importToken

  // 自動在 window unload 時嘗試儲存（如果 global 變數 CEH_CURRENT_PROGRESS 存在）
  window.addEventListener('beforeunload', async ()=>{
    try{
      const qi = window.CEH_CURRENT_QUIZ_ID
      const p = window.CEH_CURRENT_PROGRESS
      if(qi && p){
        // 不等待結果，盡力而為
        window.CEH.saveProgressToServer(qi, p)
      }
    }catch(e){console.warn(e)}
  })

})(window)
```

---

## 6) frontend/progress_ui.html (簡單示例介面，用於匯出/匯入 token)
```html
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>同步代碼匯出/匯入範例</title></head>
  <body>
    <h3>同步代碼（可複製到另一台電腦）</h3>
    <textarea id="token" rows="2" cols="60"></textarea><br>
    <button id="gen">顯示我的同步代碼</button>
    <button id="import">匯入同步代碼</button>
    <input id="importVal" placeholder="貼上代碼後按匯入" />

    <script src="save_progress.js"></script>
    <script>
      document.getElementById('gen').addEventListener('click', ()=>{
        document.getElementById('token').value = CEH.exportToken()
      })
      document.getElementById('import').addEventListener('click', ()=>{
        const v = document.getElementById('importVal').value.trim()
        if(v){ CEH.importToken(v); alert('匯入成功，請重新整理頁面以套用 token'); }
      })
    </script>
  </body>
</html>
```

---

## 7) README.md（根目錄）
```
1) 將上傳的原始專案解壓：
   unzip /mnt/data/CEH_Quiz.zip -d ./CEH_Quiz_original

2) 將本新增的 backend 與 frontend 檔案合併到專案中：
   cp -r backend ./CEH_Quiz_original/
   cp -r frontend ./CEH_Quiz_original/

3) 啟動後端（建議以虛擬環境）：
   cd CEH_Quiz_original/backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python db_init.py
   python app.py

4) 前端整合：
   - 在主要前端頁面加入 `<script src="/path/to/save_progress.js"></script>`
   - 在 quiz 初始化時，呼叫 `CEH.loadProgressFromServer(quizId).then(...)` 以載入進度
   - 在答題或重要狀態變更後呼叫 `CEH.saveProgressToServer(quizId, progressObject)`

5) 若要公開部署到遠端伺服器，請修改 `frontend/save_progress.js` 的 `API_BASE` 為公開域名，且在生產環境啟用 HTTPS 與適當的 CORS 設定。
```

---

## 注意事項與擴充建議
- 若希望使用者可透過電子郵件/帳號綁定進度，需加上使用者模型與登入流程（可採 JWT），並提供 `claim` 機制把匿名 token 與帳號合併。
- 若題目包含大量二進位資料（例如 big payload），可改為將 progress 分片或儲檔在 blob 存儲。
- 若有現有後端路由衝突，請把 API 前綴改為 `/api/ceh_quiz/...`。

---

## 我已把上面要新增/替換的檔案列出與完整程式內容，請將它們與你原有的專案合併。你上傳的原始檔案路徑：
```
/mnt/data/CEH_Quiz.zip
```

如需我直接把檔案打包成一個可下載的 ZIP（例如整合後的專案），我可以在這裡直接產生檔案並提供下載連結（會把合併/修改後的檔案寫入伺服器）。

