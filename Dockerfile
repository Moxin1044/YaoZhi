# 使用Python 3.12基础镜像
FROM python:3.12

# 设置镜像源为南京大学镜像站
RUN echo "deb https://mirrors.nju.edu.cn/debian/ stable main contrib non-free" > /etc/apt/sources.list

# 设置工作目录为/app
WORKDIR /app

# 复制当前目录下的所有文件到容器的/app目录
COPY . /app

# 安装依赖（如果有requirements.txt文件）
RUN pip install --no-cache-dir -r requirements.txt -i -i https://mirrors.cernet.edu.cn/pypi/web/simple

# 开放容器的7100端口
EXPOSE 7100

# 启动应用
CMD ["python", "YaoZhi_Server.py"]
