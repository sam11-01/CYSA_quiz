import os
import markdown, re
import firebase_admin
from flask import Flask, render_template, request, jsonify, session
from firebase_admin import credentials, firestore, auth
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "quiz-secret-key"

# ---------- Firebase ----------
cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------- 載入題庫 ----------
def load_questions():
    with open("questions.md", "r", encoding="utf-8") as f:
        text = f.read()
    blocks = re.findall(r"(## QUESTION \d+[\s\S]*?)(?=\n## QUESTION|\Z)", text)
    questions = []
    for i, block in enumerate(blocks):
        # ✅ 支援 A-Z 多選
        ans_match = re.search(r"(?:###|\>\s*\*\*)\s*Answer\s*:\s*([A-Z]+)", block, re.IGNORECASE)
        answer = ans_match.group(1).upper() if ans_match else None

        exp_match = re.search(r"### Explanation:[\s\S]*", block)
        explanation = markdown.markdown(exp_match.group(), extensions=["extra"]) if exp_match else ""

        clean = re.sub(r"### Answer:[\s\S]*", "", block)
        clean = re.sub(r"### Explanation:[\s\S]*", "", clean)
        html = markdown.markdown(clean, extensions=["extra"])

        questions.append({
            "id": len(questions) + 1,
            "html": html,
            "answer": answer,
            "explanation": explanation
        })
    print(f"✅ 載入 {len(questions)} 題")
    return questions


QUESTIONS = load_questions()

# ---------- 使用者辨識 ----------
def get_current_user():
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        id_token = token.replace("Bearer ", "").strip()
        try:
            decoded = auth.verify_id_token(id_token)
            return decoded.get("uid")
        except Exception as e:
            print("Firebase token verify failed:", e)
    # fallback 匿名
    return "anon"

# ---------- 首頁 ----------
@app.route("/")
def index():
    return render_template("quiz.html", questions=QUESTIONS, index=0)

@app.route("/q/<int:idx>")
def question(idx):
    return render_template("quiz.html", questions=QUESTIONS, index=idx)

# ---------- API: 取得使用者進度 ----------
@app.route("/api/progress")
def api_progress():
    user_id = get_current_user()
    doc = db.collection("progress").document(user_id).get()
    if doc.exists:
        data = doc.to_dict()
    else:
        data = {"answers": {}, "marks": {}, "score": 0}
    return jsonify(data)

# ---------- API: 作答 ----------
@app.route("/api/answer", methods=["POST"])
def api_answer():
    user_id = get_current_user()

    # ===== 實作題（multipart）=====
    if request.content_type.startswith("multipart/form-data"):
        idx = int(request.form["idx"])
        text = request.form.get("text", "")
        image = request.files.get("image")

        image_path = None
        if image:
            filename = secure_filename(image.filename)
            image_path = f"{UPLOAD_DIR}/{user_id}_{idx}_{filename}"
            image.save(image_path)

        q = QUESTIONS[idx]
        
        doc_ref = db.collection("progress").document(user_id)
        doc = doc_ref.get()
        if doc.exists:
            progress = doc.to_dict()
        else:
            progress = {"answers": {}, "marks": {}, "score": 0}

        progress["answers"][str(idx)] = "[PRACTICE]"
        doc_ref.set(progress)

        db.collection("records").add({
            "user": user_id,
            "question_id": q["id"],
            "text": text,
            "image": image_path,
            "type": "practice"
        })

        return jsonify({
            "ok": True,
            "explanation": q["explanation"]
        })



    data = request.json
    idx = int(data["idx"])
    choice = data["choice"]

    def normalize(s):
        return "".join(sorted(s.upper())) if s else ""
    q = QUESTIONS[idx]
    correct = normalize(choice) == normalize(q["answer"])

    # # 實作題：沒有標準答案
    # if not q["answer"]:
    #     correct = True
    # else:
    #     correct = normalize(choice) == normalize(q["answer"])

    # 取得原進度
    doc_ref = db.collection("progress").document(user_id)
    doc = doc_ref.get()
    if doc.exists:
        progress = doc.to_dict()
    else:
        progress = {"answers": {}, "marks": {}, "score": 0}

    first_time = str(idx) not in progress["answers"]
    if first_time and correct:
        progress["score"] += 1
    progress["answers"][str(idx)] = choice

    doc_ref.set(progress)
    db.collection("records").add({
        "user": user_id,
        "question_id": q["id"],
        "choice": choice,
        "correct": correct,
        "first_time": first_time
    })

    return jsonify({
        "correct": correct,
        "answer": q["answer"],
        "explanation": q["explanation"],
        "score": progress["score"],
        "first_time": first_time
    })

# ---------- API: 標記題目 ----------
@app.route("/api/mark", methods=["POST"])
def api_mark():
    data = request.json
    idx = int(data["idx"])
    mark = data["mark"]
    user_id = get_current_user()

    doc_ref = db.collection("progress").document(user_id)
    doc = doc_ref.get()
    if doc.exists:
        progress = doc.to_dict()
    else:
        progress = {"answers": {}, "marks": {}, "score": 0}

    progress["marks"][str(idx)] = mark
    doc_ref.set(progress)

    return jsonify({"ok": True, "marks": progress["marks"]})

# ---------- API: 提交成績 ----------
@app.route("/api/submit", methods=["POST"])
def api_submit():
    data = request.json
    score = data.get("score")
    total = data.get("total")
    user_id = get_current_user()
    db.collection("submissions").add({"user": user_id, "score": score, "total": total})
    return jsonify({"status":"ok","score":score,"total":total})

if __name__ == "__main__":
    # app.run(debug=True)
    app.run()
