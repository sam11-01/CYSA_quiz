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