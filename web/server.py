import os
import hashlib
import sqlite3
from flask import Flask, render_template, request, jsonify
import core
from datetime import datetime
from threading import Thread
import time

app = Flask(__name__)

# 创建上传日志文件的文件夹
UPLOAD_FOLDER = './uploads/logs/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 创建数据库连接
def get_db():
    conn = sqlite3.connect('tasks.db')
    conn.row_factory = sqlite3.Row  # Allows for column access by name
    return conn

# 初始化数据库
def init_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        task_id TEXT UNIQUE,
                        status TEXT,
                        progress INTEGER,
                        timestamp DATETIME,
                        results TEXT)''')

init_db()

# 后台分析任务
def process_task(task_id, file_path):
    # 任务开始时设定状态
    with get_db() as db:
        db.execute('''UPDATE tasks SET status = ?, progress = ? WHERE task_id = ?''',
                   ('分析中', 0, task_id))

    # 解析日志并更新进度
    data = core.batch_analysis_web(file_path)  # 解析文件
    ip_calc = core.calc_ip(data)
    ip_info = []

    # --------------------------------
    for i in ip_calc:
        message = core.get_ip_message(i['IP'])
        ip_info.append({"IP": i['IP'], "IP_Counts": i['IP_Counts'], "IP_location": message['IP_location']})
    # --------------------------------

    # 将data和ip_info转换为字符串存储在数据库
    with get_db() as db:
        db.execute('''UPDATE tasks SET status = ?, progress = ?, results = ? WHERE task_id = ?''',
                   ('完成', 100, str({'data': data, 'ip_info': ip_info}), task_id))

    # 返回分析结果
    return data, ip_info

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html')

    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            # 检查文件扩展名是否为 .log
            if not file.filename.endswith('.log'):
                return jsonify({'error': 'Only .log files are allowed'}), 400

            # 获取文件MD5值来命名文件
            md5_hash = hashlib.md5(file.read()).hexdigest()
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{md5_hash}.log")

            # 保存文件
            file.seek(0)  # Reset file pointer after reading
            file.save(file_path)

            # 创建任务ID
            task_id = md5_hash

            # 检查任务ID是否已存在
            with get_db() as db:
                existing_task = db.execute('''SELECT * FROM tasks WHERE task_id = ?''', (task_id,)).fetchone()
                if existing_task:
                    # 如果任务ID已经存在，直接返回该任务的ID
                    return jsonify({'task_id': task_id}), 200
                else:
                    # 否则插入新任务记录
                    db.execute('''INSERT INTO tasks (task_id, status, progress, timestamp) 
                                  VALUES (?, ?, ?, ?)''',
                               (task_id, '待分析', 0, datetime.now()))

            # 启动后台分析任务
            thread = Thread(target=process_task, args=(task_id, file_path))
            thread.start()

            return jsonify({'task_id': task_id}), 200

    return render_template('index.html')

# 获取任务进度
@app.route('/task_status/<task_id>', methods=['GET'])
def get_task_status(task_id):
    with get_db() as db:
        task = db.execute('''SELECT * FROM tasks WHERE task_id = ?''', (task_id,)).fetchone()

    if task:
        return jsonify({
            'task_id': task['task_id'],
            'status': task['status'],
            'progress': task['progress']
        })
    else:
        return jsonify({'error': '任务ID不存在'}), 404

# 获取任务结果
@app.route('/task_results/<task_id>', methods=['GET'])
def get_task_results(task_id):
    with get_db() as db:
        task = db.execute('''SELECT results FROM tasks WHERE task_id = ?''', (task_id,)).fetchone()

    if task and task['results']:
        results = eval(task['results'])  # 将字符串转换为字典（包括data和ip_info）
        return jsonify({'success': True, 'results': results})
    else:
        return jsonify({'success': False, 'message': '结果未完成或未找到'}), 404

if __name__ == '__main__':
    app.run(debug=True)
