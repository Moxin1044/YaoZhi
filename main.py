import cli.main

cli.main.painting()
print("\n请选择："
              "\n 1) 运行命令行界面"
              "\n 2) 运行Web界面"
              "\n\n 0) 退出程序")
console_code = input("*>请输入操作代码：")

if console_code == '1':
    cli.main.cli()
elif console_code == '2':
    pass
