from werkzeug.security import generate_password_hash

# 创建一个加密后的密码
hashed_password = generate_password_hash('12345678')

print(hashed_password)