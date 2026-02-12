# 單獨抓 PDF 圖片
import os
import fitz  # PyMuPDF

# ========= 使用者只需要改這裡 =========
PDF_PATH = "input.pdf"          # ← 你的 PDF 路徑
OUTPUT_DIR = "static/images"    # ← 圖片輸出資料夾
# ====================================

def extract_images_from_pdf(pdf_path: str, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)

    doc = fitz.open(pdf_path)
    images_saved = []
    image_counter = 1  # 圖片編號

    for page_index in range(len(doc)):
        page = doc[page_index]
        image_list = page.get_images(full=True)

        for img in image_list:
            xref = img[0]
            base_image = doc.extract_image(xref)

            image_bytes = base_image["image"]
            # 統一存成 jpeg
            img_name = f"image{image_counter}.jpeg"
            img_path = os.path.join(out_dir, img_name)

            with open(img_path, "wb") as f:
                f.write(image_bytes)

            images_saved.append({
                "page": page_index + 1,
                "name": img_name,
                "path": img_path
            })

            image_counter += 1  # 編號遞增

    doc.close()
    return images_saved

if __name__ == "__main__":
    images = extract_images_from_pdf(PDF_PATH, OUTPUT_DIR)
    print(f"共擷取 {len(images)} 張圖片")
