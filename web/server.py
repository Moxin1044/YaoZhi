from flask import Flask, render_template, request
import core

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html')
    if request.method == 'POST':
        if 'file' in request.files:
            # 处理上传的文件
            file = request.files['file']
            content = file.read().decode()
            data = core.batch_analysis_web(content)
            return render_template('index.html', datas=data)

# 默认不使用该文件启动，启动需要运行主目录下的yaozhii.py
# app.run()
