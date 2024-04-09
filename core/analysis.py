import core.read
from tqdm import tqdm
from datetime import datetime, timedelta, timezone


def parse_log_line(line):
    # 分割日志行
    parts = line.split()
    # 提取IP地址
    ip = parts[0]
    # 提取时间戳并转换为datetime对象
    time_str = parts[3][1:] + " " + parts[4][:-1]  # 去掉方括号
    time_format = "%d/%b/%Y:%H:%M:%S %z"  # 时间格式
    utc_time = datetime.strptime(time_str, time_format)
    # 转换为UTC+8时间
    utc_plus_8 = utc_time + timedelta(hours=8)
    # 提取请求方法（GET, POST等）
    request_method = parts[5][1:]
    # 提取访问页面
    request_path = parts[6]
    # 提取HTTP版本
    http_version = parts[7][:-1]
    # 提取响应值
    response_code = parts[8]
    # 提取响应大小
    response_size = parts[9]
    # 提取请求UA
    user_agent = parts[11:] if parts[-1] != "-" else None
    # 构建字典
    log_dict = {
        'IP': ip,
        'Time': utc_plus_8.strftime("%Y-%m-%d %H:%M:%S"),
        'Access Type': request_method,
        'Accessed Page': request_path,
        'HTTP Version': http_version,
        'Response Code': response_code,
        'Response Size': response_size,
        'User Agent': user_agent
    }

    return log_dict


def batch_analysis(filename):
    lines = core.read.read_file(filename)
    print(f"正在解析日志，该文件共有：{len(lines)}条日志。")
    data = []
    for l in tqdm(lines):
        data.append(parse_log_line(l))
    return data

