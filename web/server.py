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
            ip_calc = core.calc_ip(data)
            print(ip_calc)
            ip_info = []
            # --------------------------------
            for i in ip_calc:
                message = core.get_ip_message(i['IP'])
                ip_info.append({"IP": i['IP'], "IP_Counts": i['IP_Counts'], "IP_location": message['IP_location']})
            # --------------------------------
            print(ip_info)
            return render_template('index.html', datas=data, merged_list=ip_info)
    return render_template('index.html')

# 默认不使用该文件启动，启动需要运行主目录下的yaozhii.py
# app.run()
