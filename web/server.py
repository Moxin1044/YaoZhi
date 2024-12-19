from flask import Flask, render_template, request, jsonify, current_app, make_response, redirect, url_for, send_file, flash
from werkzeug.security import check_password_hash, generate_password_hash  # 用于密码验证与生成
from functools import wraps # 装饰器
import jwt # PyJWT
import hashlib
import sqlite3
import core
from datetime import datetime, timedelta
from threading import Thread
import os

app = Flask(__name__)

# 创建上传日志文件的文件夹
UPLOAD_FOLDER = './uploads/logs/'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = '0d23d17f137e04b92831d5596bb7cd1d'  # 确保使用一个复杂的密钥

# 用于生成Token
def generate_token(username, password):
    payload = {
        'username': username,
        'password': password,
        'exp': datetime.utcnow() + timedelta(days=5)  # 设置Token过期时间为5天
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

# 用于验证Token
def verify_token(token):
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload  # 返回payload信息
    except jwt.ExpiredSignatureError:
        return None  # Token过期
    except jwt.InvalidTokenError:
        return None  # Token无效


# 装饰器
def login_required(f):
    """
    装饰器：检查用户是否登录（是否有有效的Token）
    如果用户没有登录，重定向到登录页面。
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 从Cookie中获取Token
        token = request.cookies.get('auth_token')
        # 验证Token有效性
        user_data = verify_token(token)
        # 如果Token无效或不存在，重定向到登录页面
        if not user_data:
            return redirect(url_for('admin_login'))
        # Token有效，继续执行视图函数
        return f(*args, **kwargs)
    return decorated_function


def login_required_for_admin(f):
    """
    装饰器：如果用户已经登录，重定向到管理员首页。
    如果用户未登录，允许访问登录页面。
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 从Cookie中获取Token
        token = request.cookies.get('auth_token')

        # 验证Token有效性
        user_data = verify_token(token)

        # 如果用户已经登录，重定向到管理员首页
        if user_data:
            return redirect(url_for('admin'))  # 已登录则跳转到管理员首页

        # 如果没有登录，继续执行视图函数
        return f(*args, **kwargs)

    return decorated_function


# 记录用户访问日志
def log_user_activity(ip, time, ua):
    conn = get_db()
    conn.execute('''
        INSERT INTO logs (ip, time, ua)
        VALUES (?, ?, ?)
    ''', (ip, time, ua))
    conn.commit()

# 记录登录日志
def record_login(ip, username, password):
    """
    记录每次登录的IP、用户名、密码和时间到数据库。

    :param ip: 登录的IP地址
    :param username: 登录的用户名
    :param password: 登录的密码（一般不建议存储密码原文，实际应用中应存储加密后的密码）
    """
    try:
        # 获取数据库连接
        conn = get_db()  # 假设get_db()是您之前的数据库连接函数
        cursor = conn.cursor()

        # 获取当前时间
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 插入数据到login表
        cursor.execute('''
            INSERT INTO login (ip, username, password, time)
            VALUES (?, ?, ?, ?)
        ''', (ip, username, password, current_time))

        # 提交事务并关闭连接
        conn.commit()
        conn.close()
        print("Login record added successfully.")
    except Exception as e:
        print("Error recording login:", e)

# 创建数据库连接
def get_db():
    conn = sqlite3.connect('tasks.db')
    conn.row_factory = sqlite3.Row  # Allows for column access by name
    return conn

# 获取用户数据
def get_user_from_db(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


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
        db.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                        ip TEXT,
                        time DATE,
                        ua TEXT);''')
        db.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL UNIQUE,
                      password TEXT NOT NULL);''')
        db.execute('''CREATE TABLE IF NOT EXISTS settings (
                      id integer NOT NULL,
                      platform_name TEXT NOT NULL,
                      platform_keyword TEXT NOT NULL,
                      paltform_descrip TEXT NOT NULL,
                      logs integer NOT NULL DEFAULT 1,
                      login integer NOT NULL DEFAULT 1,
                      upload integer NOT NULL DEFAULT 1);''')
        db.execute('''CREATE TABLE IF NOT EXISTS login (
                      id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                      ip TEXT,
                      username TEXT,
                      password TEXT,
                      time DATE);''')
        # 获取数据库连接
        conn = get_db()
        cursor = conn.cursor()

        # 检查是否存在id=1的数据
        cursor.execute("SELECT * FROM settings WHERE id = 1")
        result = cursor.fetchone()

        if result:
            # 如果存在id=1的数据，打印信息并返回
            print("数据已存在，id=1的数据不处理。")
        else:
            # 如果不存在id=1的数据，执行插入操作
            cursor.execute('''INSERT INTO settings (id, platform_name, platform_keyword, paltform_descrip, logs, login, upload)
                                 VALUES (1, ?, ?, ?, 1, 1, 1)''', (
                '遥知 - Web日志分析',
                '遥知，Web日志分析，在线日志分析，日志工具，即现日志，日志分析工具，分析工具，日志检查，日志审计',
                '遥知是一款在线日志分析工具，能够方便统计Web日志、请求者访问频次、快速检索日志内容，进行日志处理。'
            ))
            conn.commit()
            print("插入数据成功！")
            # 检查是否存在id=1的数据
            cursor.execute("SELECT * FROM users WHERE id = 1")
            result = cursor.fetchone()

            if result:
                # 如果存在id=1的数据，打印信息并返回
                print("数据已存在，id=1的数据不处理。")
            else:
                # 如果不存在id=1的数据，执行插入操作
                cursor.execute('''INSERT INTO users (id, username, password)
                                         VALUES (1, ?, ?)''', (
                    'admin',
                    'scrypt:32768:8:1$KsdX2OrPiXMBseJK$5e088655560ca145ecaa9232da9715fbcb862a9ad17b42eb040119ca4e3d032ccd95cbbc260a1cb52842b301ee168d86b0f4e2efff81969b3b19b7200f8d8955'
                ))
                conn.commit()
                print("插入数据成功！")


init_db() # 初始化



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

    with get_db() as db:
        db.execute('''UPDATE tasks SET status = ?, progress = ? WHERE task_id = ?''',
                   ('分析中', 50, task_id))
    # --------------------------------
    for i in ip_calc:
        message = core.get_ip_message(i['IP'])
        ip_info.append({"IP": i['IP'], "IP_Counts": i['IP_Counts'], "IP_location": message['IP_location']})
    # --------------------------------
    with get_db() as db:
        db.execute('''UPDATE tasks SET status = ?, progress = ? WHERE task_id = ?''',
                   ('分析中', 80, task_id))
    # 将data和ip_info转换为字符串存储在数据库
    with get_db() as db:
        db.execute('''UPDATE tasks SET status = ?, progress = ?, results = ? WHERE task_id = ?''',
                   ('完成', 100, str({'data': data, 'ip_info': ip_info}), task_id))
    # 返回分析结果
    return data, ip_info

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        # 用户请求分析
        ip = request.remote_addr  # 获取IP地址
        ua = request.headers.get('User-Agent')  # 获取浏览器的User-Agent
        nowtime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # 获取当前时间
        if is_access_stats_enabled():
            # 异步写入日志
            Thread(target=log_user_activity, args=(ip, nowtime, ua)).start()


        return render_template('index.html')

    if request.method == 'POST':

        if is_upload_permission_enabled():
            print("允许文件上传")
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
        else:
            print("禁止文件上传")
            return jsonify({'task_id': 0}), 200

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


# 通过Token验证用户并访问admin页面
@app.route('/admin/login', methods=['GET', 'POST'])
@login_required_for_admin
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # 判断是否开启了登录日志
        if is_admin_login_stats_enabled():
            ip = request.remote_addr  # 获取IP地址
            record_login(ip, username, password) # 作登录日志使用
        # 从数据库查询用户信息
        user = get_user_from_db(username)
        if user and check_password_hash(user[1], password):  # user[1]是数据库中的password
            # 生成Token
            token = generate_token(username, password)
            # 创建响应并设置Cookie（或其他方式，如LocalStorage）
            response = make_response(redirect(url_for('admin')))
            response.set_cookie('auth_token', token)
            return response
        # 如果用户名或密码错误，返回错误信息
        return render_template('admin/login.html', error="用户名或密码错误")
    # 如果是GET请求，直接返回登录页面
    return render_template('admin/login.html')

# 退出登录

@app.route('/admin/logout', methods=['GET'])
@login_required
def admin_logout():
    # 清除用户的auth_token Cookie
    response = make_response(redirect(url_for('admin_login')))
    response.delete_cookie('auth_token')  # 删除Cookie，清除登录状态
    return response



@app.route('/admin', methods=['GET'])
@login_required
def admin():
    # 从Cookie中获取Token
    token = request.cookies.get('auth_token')
    # 验证Token有效性
    user_data = verify_token(token)
    # 如果Token有效，获取用户名
    username = user_data.get('username')
    # 传递用户名到模板
    return render_template('admin/index.html', username=username)

@app.route('/admin/home', methods=['GET'])
@login_required
def admin_home():
    # 如果Token有效，进入正常功能
    return render_template('admin/home.html')


@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        # 获取表单数据
        platform_name = request.form.get('platform_name')
        platform_keywords = request.form.get('platform_keywords')
        platform_description = request.form.get('platform_description')
        enable_access_stats = 1 if request.form.get('enable_access_stats') else 0
        enable_admin_login_stats = 1 if request.form.get('enable_admin_login_stats') else 0
        enable_upload = 1 if request.form.get('enable_upload') else 0

        # 更新数据库中的设置
        cursor.execute('''UPDATE settings
                          SET platform_name = ?, platform_keyword = ?, paltform_descrip = ?, logs = ?, login = ?, upload = ?
                          WHERE id = 1''', (
            platform_name, platform_keywords, platform_description, enable_access_stats,
            enable_admin_login_stats, enable_upload))

        conn.commit()
        flash("设置已保存成功", "success")
        return redirect(url_for('admin_settings'))

    # 查询当前设置的数据
    cursor.execute("SELECT * FROM settings WHERE id = 1")
    setting = cursor.fetchone()

    conn.close()
    return render_template('admin/settings/Settings.html', setting=setting)


@app.route('/admin/settings/Modify_Password', methods=['GET', 'POST'])
@login_required
def admin_settings_Modify_Password():
    if request.method == 'POST':
        # 获取表单数据
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        # 从Cookie中获取Token
        token = request.cookies.get('auth_token')
        # 验证Token有效性
        user_data = verify_token(token)
        # 获取当前用户的用户名（假设已经通过token获取了用户信息）
        username = user_data['username']  # 这是你从token解码得到的用户信息

        # 验证密码是否一致
        if new_password != confirm_password:
            flash('新密码和确认密码不一致', 'error')
            return redirect(url_for('admin_settings_Modify_Password'))

        # 获取数据库连接
        conn = get_db()
        cursor = conn.cursor()

        # 查询用户的当前密码
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], current_password):
            # 当前密码正确，更新密码
            hashed_password = generate_password_hash(new_password)
            cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
            conn.commit()

            flash('密码修改成功', 'success')
            return redirect(url_for('admin_settings_Modify_Password'))
        else:
            # 当前密码不正确
            flash('当前密码错误', 'error')
            return redirect(url_for('admin_settings_Modify_Password'))
    return render_template('admin/settings/Modify_Password.html')



@app.route('/admin/task/Task_Management', methods=['GET', 'POST'])
@login_required
def admin_task_Management():
    # 从Cookie中获取Token
    token = request.cookies.get('auth_token')
    # 验证Token有效性
    user_data = verify_token(token)
    if not user_data:
        return redirect(url_for('admin_login'))

    # 获取页码，默认为1
    page = int(request.args.get('page', 1))
    search = request.args.get('search', '')

    conn = get_db()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 查询任务总数
    cursor.execute('SELECT COUNT(*) FROM tasks WHERE task_id LIKE ?', ('%' + search + '%',))
    total_tasks = cursor.fetchone()[0]

    # 每页显示20条
    per_page = 20
    total_pages = (total_tasks + per_page - 1) // per_page
    offset = (page - 1) * per_page

    # 查询当前页任务
    cursor.execute('''
        SELECT * FROM tasks
        WHERE task_id LIKE ?
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    ''', ('%' + search + '%', per_page, offset))
    tasks = cursor.fetchall()

    return render_template('admin/task/Task_Management.html',
                           tasks=tasks,
                           current_page=page,
                           total_pages=total_pages)


@app.route('/admin/task/delete', methods=['POST', 'GET'])
@login_required
def admin_task_delete():
    # 获取选中的任务 ID 列表
    task_ids = request.form.getlist('ids[]')  # 注意，Flask 会自动将 `ids[]` 解析为列表
    if not task_ids:
        return jsonify({'status': 'error', 'message': '没有选中任务'}), 400

    # 删除选中的任务
    try:
        conn = get_db()
        cursor = conn.cursor()
        # 删除任务
        cursor.executemany('DELETE FROM tasks WHERE id = ?', [(task_id,) for task_id in task_ids])
        conn.commit()

        return jsonify({'status': 'success', 'message': '任务删除成功'})
    except sqlite3.DatabaseError as e:
        # 记录数据库错误
        app.logger.error(f"Database error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    except Exception as e:
        # 记录其他未知错误
        app.logger.error(f"Unexpected error: {e}")
        return jsonify({'status': 'error', 'message': '发生未知错误'}), 500


@app.route('/admin/task/download/<task_id>', methods=['GET'])
@login_required
def admin_task_download(task_id):
    log_filename = f"{task_id}.log"
    log_path = os.path.join(app.config['UPLOAD_FOLDER'], log_filename)
    absolute_path = os.path.abspath(log_path)
    # Debugging the log path
    print(f"Log path: {log_path}")
    print(absolute_path)

    if os.path.exists(absolute_path):
        return send_file(absolute_path, log_filename, as_attachment=True)
    else:
        return "日志文件不存在"


@app.route('/admin/task/clear_all', methods=['POST'])
@login_required
def admin_task_clear_all():
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM tasks')
        conn.commit()
        return "清空所有任务成功", 200
    except Exception as e:
        conn.rollback()
        return f"清空失败: {e}", 500
    finally:
        conn.close()



# 新增用户
@app.route('/admin/personnel/add_user', methods=['POST'])
@login_required
def add_user():
    username = request.form['username']
    password = request.form['password']
    hashed_password = generate_password_hash(password)

    conn = get_db()
    conn.execute('INSERT INTO users (username, password) VALUES (?, ?);', (username, hashed_password))
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": "新增用户成功"})


# 删除用户
@app.route('/admin/personnel/delete_user', methods=['POST'])
@login_required
def delete_user():
    user_ids = request.json.get('user_ids')  # 获取传递的user_ids
    if user_ids:
        conn = get_db()
        # 通过'?'占位符的方式避免SQL注入
        query = 'DELETE FROM users WHERE id IN (' + ','.join(['?'] * len(user_ids)) + ')'
        conn.execute(query, user_ids)  # 使用元组传递参数
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "删除成功"})

    return jsonify({"status": "error", "message": "删除失败"}), 400


# 用户管理页面（分页和搜索）
@app.route('/admin/personnel/User_Management', methods=['GET'])
@login_required
def admin_personne_User_Management():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()

    conn = get_db()
    offset = (page - 1) * 20
    if search_query:
        users = conn.execute('''
            SELECT * FROM users WHERE username LIKE ? ORDER BY id DESC LIMIT 20 OFFSET ?;
        ''', ('%' + search_query + '%', offset)).fetchall()
        total_count = \
        conn.execute('SELECT COUNT(*) FROM users WHERE username LIKE ?;', ('%' + search_query + '%',)).fetchone()[0]
    else:
        users = conn.execute('''
            SELECT * FROM users ORDER BY id DESC LIMIT 20 OFFSET ?;
        ''', (offset,)).fetchall()
        total_count = conn.execute('SELECT COUNT(*) FROM users;').fetchone()[0]

    conn.close()

    total_pages = (total_count + 19) // 20  # 向上取整

    return render_template('admin/personnel/User_Management.html', users=users, page=page, total_pages=total_pages,
                           search_query=search_query)

@app.route('/admin/personnel/Customer_Analysis', methods=['GET', 'POST'])
@login_required
def admin_personne_Customer_Analysis():
    # 获取搜索条件
    search_query = request.args.get('search', '')
    page = int(request.args.get('page', 1))  # 获取当前页码，默认为1

    # 每页显示30条日志
    per_page = 30
    offset = (page - 1) * per_page

    # 获取数据库连接
    conn = get_db()

    # 根据搜索条件查询
    if search_query:
        cursor = conn.execute('''
                SELECT * FROM logs
                WHERE ip LIKE ? OR ua LIKE ? OR time LIKE ?
                ORDER BY time DESC
                LIMIT ? OFFSET ?
            ''', ('%' + search_query + '%', '%' + search_query + '%', '%' + search_query + '%', per_page, offset))
    else:
        cursor = conn.execute('''
                SELECT * FROM logs
                ORDER BY time DESC
                LIMIT ? OFFSET ?
            ''', (per_page, offset))

    logs = cursor.fetchall()

    # 获取总页数
    cursor = conn.execute('SELECT COUNT(*) FROM logs')
    total_logs = cursor.fetchone()[0]
    total_pages = (total_logs + per_page - 1) // per_page  # 计算总页数

    return render_template('admin/personnel/Customer_Analysis.html', logs=logs, search_query=search_query, page=page, total_pages=total_pages)

@app.route('/admin/clear_logs', methods=['POST'])
@login_required
def clear_logs():
    # 获取数据库连接
    conn = get_db()
    try:
        # 清空日志表
        conn.execute('DELETE FROM logs')
        conn.commit()
        return jsonify({"status": "success", "message": "日志已清空"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"清空失败: {str(e)}"}), 400
    
    
@app.route('/admin/settings/Login_Logs', methods=['GET', 'POST'])
@login_required
def admin_settings_Login_Logs():
    # 获取搜索条件
    search_query = request.args.get('search', '')
    page = int(request.args.get('page', 1))  # 获取当前页码，默认为1

    # 每页显示30条日志
    per_page = 30
    offset = (page - 1) * per_page

    # 获取数据库连接
    conn = get_db()

    # 根据搜索条件查询
    if search_query:
        cursor = conn.execute('''
                SELECT * FROM login
                WHERE ip LIKE ? OR username LIKE ? OR password LIKE ? OR time LIKE ?
                ORDER BY time DESC
                LIMIT ? OFFSET ?
            ''', ('%' + search_query + '%', '%' + search_query + '%', '%' + search_query + '%', '%' + search_query + '%', per_page, offset))
    else:
        cursor = conn.execute('''
                SELECT * FROM login
                ORDER BY time DESC
                LIMIT ? OFFSET ?
            ''', (per_page, offset))

    logs = cursor.fetchall()

    # 获取总页数
    cursor = conn.execute('SELECT COUNT(*) FROM login')
    total_logs = cursor.fetchone()[0]
    total_pages = (total_logs + per_page - 1) // per_page  # 计算总页数

    return render_template('admin/settings/Login_Logs.html', logs=logs, search_query=search_query, page=page, total_pages=total_pages)


@app.route('/admin/clear_login_logs', methods=['POST'])
@login_required
def clear_login_logs():
    # 获取数据库连接
    conn = get_db()

    try:
        # 清空日志表
        conn.execute('DELETE FROM login')
        conn.commit()
        return jsonify({"status": "success", "message": "日志已清空"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"清空失败: {str(e)}"}), 400


@app.route('/api/get_all_logs', methods=['GET'])
@login_required
def api_get_all_logs():
    conn = get_db()
    cursor = conn.execute('SELECT id, ip, time, ua FROM logs')
    logs = cursor.fetchall()

    # 将日志转换为字典列表
    log_list = []
    for log in logs:
        log_list.append({
            "id": log["id"],
            "ip": log["ip"],
            "time": log["time"],
            "ua": log["ua"]
        })

    # 返回日志列表作为JSON响应
    return jsonify(log_list)


@app.route('/api/get_all_tasks', methods=['GET'])
@login_required
def api_get_all_tasks():
    conn = get_db()
    cursor = conn.execute('SELECT id, task_id, status, progress, timestamp,results  FROM tasks')
    tasks = cursor.fetchall()

    # 将日志转换为字典列表
    task_list = []
    for task in tasks:
        task_list.append({
            "id": task["id"],
            "task_id": task["task_id"],
            "status": task["status"],
            "progress": task["progress"],
            "timestamp": task["timestamp"],
            "results": task["results"]
        })

    # 返回日志列表作为JSON响应
    return jsonify(task_list)



@app.route('/api/get_logs_count', methods=['GET'])
@login_required
def api_get_logs_count():
    # 从Cookie中获取Token
    token = request.cookies.get('auth_token')
    # 验证Token有效性
    user_data = verify_token(token)
    if user_data:
        conn = get_db()
        cursor = conn.execute('SELECT id FROM logs')
        ret_data = {"count": cursor.fetchall().__len__()}
        # 返回日志列表作为JSON响应
        return jsonify(ret_data)
    # 如果Token无效或不存在，重定向到登录页面
    return redirect(url_for('admin_login'))


@app.route('/api/get_users_count', methods=['GET'])
@login_required
def api_get_users_count():
    conn = get_db()
    cursor = conn.execute('SELECT id FROM users')
    ret_data = {"count": cursor.fetchall().__len__()}
    # 返回日志列表作为JSON响应
    return jsonify(ret_data)


@app.route('/api/get_tasks_count', methods=['GET'])
@login_required
def api_get_tasks_count():
    conn = get_db()
    cursor = conn.execute('SELECT id FROM tasks')
    ret_data = {"count": cursor.fetchall().__len__()}
    # 返回日志列表作为JSON响应
    return jsonify(ret_data)



@app.route('/api/get_task_true_count', methods=['GET'])
@login_required
def api_get_tasks_true_count():
    conn = get_db()
    cursor = conn.execute("SELECT id FROM tasks WHERE status = '完成'")
    ret_data = {"count": cursor.fetchall().__len__()}
    # 返回日志列表作为JSON响应
    return jsonify(ret_data)


@app.route('/api/get_task_false_count', methods=['GET'])
@login_required
def api_get_tasks_false_count():
    conn = get_db()
    cursor = conn.execute("SELECT id FROM tasks WHERE status = '分析中'")
    ret_data = {"count": cursor.fetchall().__len__()}
    # 返回日志列表作为JSON响应
    return jsonify(ret_data)


@app.route('/api/get_today_tasks_count', methods=['GET'])
@login_required
def api_get_today_tasks_count():
    conn = get_db()
    # 获取当前日期（年月日）
    today_date = datetime.today().strftime('%Y-%m-%d')
    # 查询数据库，获取今天的任务（只取日期部分进行比较）
    cursor = conn.execute('''
        SELECT id, task_id, status, progress, timestamp, results
        FROM tasks
        WHERE DATE(timestamp) = ?
    ''', (today_date,))
    ret_data = {"count": cursor.fetchall().__len__()}
    # 返回任务列表
    return jsonify(ret_data)


@app.route('/api/get_past_7_days_tasks_count', methods=['GET'])
@login_required
def api_get_past_7_days_tasks_count():
    conn = get_db()
    # 查询过去7天的数据
    cursor = conn.execute('''
        SELECT id, task_id, status, progress, timestamp, results
        FROM tasks
        WHERE timestamp >= DATE('now', '-7 days')
    ''')
    ret_data = {"count": len(cursor.fetchall())}
    return jsonify(ret_data)


@app.route('/api/get_this_month_tasks_count', methods=['GET'])
@login_required
def api_get_this_month_tasks_count():
    conn = get_db()
    # 查询本月的数据
    cursor = conn.execute('''
        SELECT id, task_id, status, progress, timestamp, results
        FROM tasks
        WHERE timestamp >= strftime('%Y-%m-01', 'now')
    ''')
    ret_data = {"count": len(cursor.fetchall())}
    return jsonify(ret_data)



@app.route('/api/get_last_7_days_task_count', methods=['GET'])
@login_required
def api_get_last_7_days_task_count():
    conn = get_db()
    # 获取当前日期
    today = datetime.today()
    # 获取过去 7 天的日期范围
    last_7_days = [today - timedelta(days=i) for i in range(7)]
    # 格式化日期为 "MM-DD"
    last_7_days_formatted = [date.strftime('%m-%d') for date in last_7_days]
    # 统计每天任务数量
    task_counts = []
    for day in last_7_days:
        # 获取每一天的任务数量
        cursor = conn.execute('''
            SELECT COUNT(*) 
            FROM tasks
            WHERE DATE(timestamp) = ?
        ''', (day.strftime('%Y-%m-%d'),))  # 使用 YYYY-MM-DD 格式
        count = cursor.fetchone()[0]
        task_counts.append(count)
    # 返回结果：labels 是日期，data 是每个日期的任务数量
    result = {
        "labels": last_7_days_formatted,
        "data": task_counts
    }
    return jsonify(result)


@app.route('/api/get_last_30_days_logs_count', methods=['GET'])
@login_required
def api_get_last_30_days_logs_count():
    conn = get_db()
    # 获取当前日期
    today = datetime.today()
    # 获取过去 30 天的日期范围
    last_30_days = [today - timedelta(days=i) for i in range(30)]
    # 格式化日期为 "MM-DD"
    last_30_days_formatted = [date.strftime('%m-%d') for date in last_30_days]
    # 统计每天的日志访问次数
    log_counts = []
    for day in last_30_days:
        # 获取每一天的访问次数
        cursor = conn.execute('''
            SELECT COUNT(*) 
            FROM logs
            WHERE DATE(time) = ?
        ''', (day.strftime('%Y-%m-%d'),))  # 使用 YYYY-MM-DD 格式
        count = cursor.fetchone()[0]
        log_counts.append(count)

    # 返回结果：labels 是日期（格式化为 MM-DD），data 是每个日期的访问次数
    result = {
        "labels": last_30_days_formatted,
        "data": log_counts
    }
    return jsonify(result)


@app.route('/api/get_platform_info', methods=['GET']) # 这个接口不需要鉴权 别问 问就是不用
def get_platform_info():
    # 获取数据库连接
    conn = get_db()
    cursor = conn.cursor()
    # 查询设置数据
    cursor.execute("SELECT platform_name, platfrom_keyword, paltfrom_descrip FROM settings WHERE id = 1")
    setting = cursor.fetchone()
    conn.close()
    # 返回结果
    if setting:
        return {
            "platform_name": setting["platform_name"],
            "platform_keywords": setting["platfrom_keyword"],
            "platform_description": setting["paltfrom_descrip"]
        }
    else:
        return {"error": "Settings not found"}, 404


@app.route('/api/get_access_stats', methods=['GET'])
@login_required
def get_access_stats():
    # 获取数据库连接
    conn = get_db()
    cursor = conn.cursor()
    # 查询设置数据
    cursor.execute("SELECT logs FROM settings WHERE id = 1")
    setting = cursor.fetchone()
    conn.close()
    # 判断logs字段值，返回结果
    if setting:
        return {"access_stats_enabled": True if setting["logs"] == 1 else False}
    else:
        return {"error": "Settings not found"}, 404


@app.route('/api/get_admin_login_stats', methods=['GET'])
@login_required
def get_admin_login_stats():
    # 获取数据库连接
    conn = get_db()
    cursor = conn.cursor()
    # 查询设置数据
    cursor.execute("SELECT login FROM settings WHERE id = 1")
    setting = cursor.fetchone()
    conn.close()
    # 判断login字段值，返回结果
    if setting:
        return {"admin_login_stats_enabled": True if setting["login"] == 1 else False}
    else:
        return {"error": "Settings not found"}, 404


@app.route('/api/get_upload_permission', methods=['GET'])
@login_required
def get_upload_permission():
    # 获取数据库连接
    conn = get_db()
    cursor = conn.cursor()
    # 查询设置数据
    cursor.execute("SELECT upload FROM settings WHERE id = 1")
    setting = cursor.fetchone()
    conn.close()
    # 判断upload字段值，返回结果
    if setting:
        return {"upload_permission_enabled": True if setting["upload"] == 1 else False}
    else:
        return {"error": "Settings not found"}, 404

# 获取平台信息
def get_platform_info_from_db():
    # 获取数据库连接
    conn = get_db()
    cursor = conn.cursor()

    # 查询平台信息
    cursor.execute("SELECT platform_name, platfrom_keyword, paltfrom_descrip FROM settings WHERE id = 1")
    setting = cursor.fetchone()

    conn.close()

    if setting:
        return {
            "platform_name": setting["platform_name"],
            "platform_keywords": setting["platfrom_keyword"],
            "platform_description": setting["paltfrom_descrip"]
        }
    else:
        return None


# 获取是否开启记录访问者
def is_access_stats_enabled():
    # 获取数据库连接
    conn = get_db()
    cursor = conn.cursor()

    # 查询是否开启访问统计
    cursor.execute("SELECT logs FROM settings WHERE id = 1")
    setting = cursor.fetchone()

    conn.close()

    if setting:
        return True if setting["logs"] == 1 else False
    else:
        return None


# 获取是否记录登录信息
def is_admin_login_stats_enabled():
    # 获取数据库连接
    conn = get_db()
    cursor = conn.cursor()

    # 查询是否开启后台登录统计
    cursor.execute("SELECT login FROM settings WHERE id = 1")
    setting = cursor.fetchone()

    conn.close()

    if setting:
        return True if setting["login"] == 1 else False
    else:
        return None

# 获取是否启用上传
def is_upload_permission_enabled():
    # 获取数据库连接
    conn = get_db()
    cursor = conn.cursor()

    # 查询是否允许上传
    cursor.execute("SELECT upload FROM settings WHERE id = 1")
    setting = cursor.fetchone()

    conn.close()

    if setting:
        return True if setting["upload"] == 1 else False
    else:
        return None





if __name__ == '__main__':
    app.run(debug=True)
