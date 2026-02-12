import markdown
from pathlib import Path

def markdown_to_html(md_path, html_path):
    md_text = Path(md_path).read_text(encoding="utf-8")

    html = markdown.markdown(
        md_text,
        extensions=[
            "extra",        # 表格、定義清單
            "codehilite",   # 程式碼高亮
            "toc",          # 目錄
            "tables"
        ]
    )

    full_html = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <title>Markdown Render</title>
    <style>
        body {{
            font-family: Arial, "Noto Sans TC", sans-serif;
            line-height: 1.6;
            max-width: 900px;
            margin: auto;
            padding: 2rem;
        }}
        pre {{
            background: #f5f5f5;
            padding: 1rem;
            overflow-x: auto;
        }}
        code {{
            background: #eee;
            padding: 2px 4px;
        }}
        blockquote {{
            border-left: 4px solid #ccc;
            padding-left: 1rem;
            color: #555;
        }}
    </style>
</head>
<body>
{html}
</body>
</html>
"""

    Path(html_path).write_text(full_html, encoding="utf-8")
    print(f"✅ 轉換完成：{html_path}")

if __name__ == "__main__":
    markdown_to_html("questions.md", "questions.html")
