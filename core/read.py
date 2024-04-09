import re


# 读取文件
def read_files(filename):
    try:
        with open(filename, 'r') as f:
            data = f.read()
        return data
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return None


# 对日志进行行存储。
def lines_logs_type(data):
    lines = [line.rstrip('\n') for line in data.split('\n') if line]
    return lines


def read_file(filename):
    return lines_logs_type(read_files(filename))