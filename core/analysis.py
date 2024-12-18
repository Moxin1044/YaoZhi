import core.read
from tqdm import tqdm
from datetime import datetime, timedelta, timezone
from collections import Counter
import requests
import json
import ast


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
        'Access_Type': request_method,
        'Accessed_Page': request_path,
        'HTTP_Version': http_version,
        'Response_Code': response_code,
        'Response_Size': response_size,
        'User_Agent': user_agent
    }

    return log_dict


def batch_analysis(filename):
    lines = core.read.read_file(filename)
    print(f"正在解析日志，该文件共有：{len(lines)}条日志。")
    data = []
    for l in tqdm(lines):
        data.append(parse_log_line(l))
    return data


def batch_analysis_web(file_read):
    lines = core.read.read_file(file_read)
    print(f"正在解析日志，该文件共有：{len(lines)}条日志。")
    data = []
    for l in tqdm(lines):
        data.append(parse_log_line(l))
    print(data)
    return data


def calc_ip(data):
    # 提取IP并统计出现次数
    ip_counts = Counter((line['IP'] for line in data))

    # 根据IP和Time创建一个排序键函数
    def sort_key(ip):
        count = ip_counts[ip]
        latest_time = max(datetime.strptime(line['Time'], "%Y-%m-%d %H:%M:%S") for line in data if line['IP'] == ip)
        return (-count, latest_time)

    # 提取所有唯一的IP地址，并根据sort_key进行排序
    sorted_ips = sorted(ip_counts.keys(), key=sort_key)
    ip_list = []
    # 打印排序后的IP列表
    for ip in sorted_ips:
        ip_list.append({"IP": ip, "IP_Counts": ip_counts[ip]})
    return ip_list


def list_ip(data):
    unique_ips_list = list(dict.fromkeys(line['IP'] for line in data))
    return unique_ips_list


def get_ip_info(ip):
    response = requests.get(f"https://opendata.baidu.com/api.php?query={ip}&co=&resource_id=6006&oe=utf8")
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Response status code: {response.status_code}")
        return 0


def ip_location(data):
    ip_list = list_ip(data)
    list_ip_info = []

    for ip in ip_list:
        info = get_ip_info(ip)['data']
        if not info:
            list_ip_info = {"IP": ip, "IP_location": "保留地址/特殊地址"}
        else:
            dst = info[0]
            list_ip_info = {"IP": ip, "IP_location": dst['location']}
    return list_ip_info


def get_ip_message(ip):
    info = get_ip_info(ip)['data']
    # 去除字符串中的方括号，然后使用ast.literal_eval安全地将其转换为Python对象（在这种情况下是一个列表）
    if not info:
        ip_info = {"IP": ip, "IP_location": "保留地址/特殊地址"}
    else:
        dst = info[0]
        ip_info = {"IP": ip, "IP_location": dst['location']}
    return ip_info