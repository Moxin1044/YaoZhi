import re

# 读取文件
def read_files(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = f.read()  # 读取整个文件内容
        return data
    except Exception as e:
        print(f"读取文件时出错: {e}")  # 打印具体的错误信息
        return None  # 返回 None，表示读取失败


# 对日志进行行存储
def lines_logs_type(data):
    if not data:  # 如果数据为空或None，返回空列表
        print("警告: 传入了无效数据。")
        return []
    lines = [line.rstrip('\n') for line in data.split('\n') if line]  # 处理每一行数据
    return lines


def read_file(filename):
    data = read_files(filename)  # 获取文件内容
    if data is None:  # 如果读取失败，直接返回空列表
        print(f"错误: 无法读取文件 {filename}.")
        return []
    return lines_logs_type(data)  # 处理并返回有效的日志行


# 旧版本Web日志（没有任务ID）
# def read_file_web(filename):
#     return lines_logs_type(filename)