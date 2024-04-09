import re
import os
import core
from prettytable import PrettyTable


# 清屏函数，适用于大多数Unix-like系统（包括Linux和macOS）
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def welcome():
    print(""" __     __        _______     _ 
 \ \   / /       |___  / |   (_)
  \ \_/ /_ _  ___   / /| |__  _ 
   \   / _` |/ _ \ / / | '_ \| |
    | | (_| | (_) / /__| | | | |
    |_|\__,_|\___/_____|_| |_|_|
                                
                                """)
    path = input("*>请输入需要分析的日志文件绝对路径：")
    if os.path.exists(path):
        data = core.batch_analysis(path)
        # clear_screen()
        # 创建表格对象
        table = PrettyTable()

        # 添加表头
        table.field_names = ["IP", "Time", "Access Type", "Accessed Page", "HTTP Version", "Response Code", "Response Size", "User Agent"]

        # 填充表格数据
        # 填充表格数据
        for item in data:
            table.add_row([
                item['IP'],
                item['Time'],
                item['Access Type'],
                item['Accessed Page'],
                item['HTTP Version'],
                item['Response Code'],
                item['Response Size'],
                item['User Agent']
            ])

            # 输出表格
        print(table)

    else:
        print(f"文件 {path} 不存在")


welcome()
