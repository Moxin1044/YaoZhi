import re
import os
import core
import pandas as pd
from prettytable import PrettyTable


# 清屏函数，适用于大多数Unix-like系统（包括Linux和macOS）
# def clear_screen():
#     os.system('cls' if os.name == 'nt' else 'clear')


def painting():
    print("""
     __     __        _______     _ 
     \ \   / /       |___  / |   (_)
      \ \_/ /_ _  ___   / /| |__  _ 
       \   / _` |/ _ \ / / | '_ \| |
        | | (_| | (_) / /__| | | | |
        |_|\__,_|\___/_____|_| |_|_|

                                    """)


def cli():
    path = input("*>请输入需要分析的日志文件绝对路径：")
    if os.path.exists(path):
        data = core.batch_analysis(path)
        # clear_screen()
        # 创建表格对象
        table = PrettyTable()

        # 添加表头
        table.field_names = ["IP", "Time", "Access Type", "Accessed Page", "HTTP Version", "Response Code",
                             "Response Size", "User Agent"]

        # 填充表格数据
        # 填充表格数据
        for item in data:
            table.add_row([
                item['IP'],
                item['Time'],
                item['Access_Type'],
                item['Accessed_Page'],
                item['HTTP_Version'],
                item['Response_Code'],
                item['Response_Size'],
                item['User_Agent']
            ])
        # 输出表格
        print(table)

        print("\n继续操作："
              "\n 1) 将结果导出为out.xlsx"
              "\n 2) 继续分析其他文件"
              "\n 3) 统计IP频次与地址"
              "\n\n 0) 退出程序")
        console_code = input("*>请输入操作代码：")
        if console_code == '1':
            # pandas DataFrame
            df = pd.DataFrame(data)
            # 导出为xlsx文件
            df.to_excel(os.getcwd() + "\\output\\output.xlsx", index=False)
        elif console_code == '2':
            cli()
        elif console_code == '3':
            ip_calc = core.calc_ip(data)
            table = PrettyTable()
            table.field_names = ["IP", "Counts"]
            for item in ip_calc:
                table.add_row([
                    item['IP'],
                    item['IP_Counts']
                ])
            # 输出表格
            print(table)
            ip_loc = core.ip_location(data)
            table = PrettyTable()
            table.field_names = ["IP", "Nation", "Continent", "City"]
            for item in ip_loc:
                table.add_row([
                    item['IP'],
                    item['IP_nation'],
                    item['IP_continent'],
                    item['IP_city']
                ])
            print(table)
        else:
            return 0
    else:
        print(f"文件 {path} 不存在")
