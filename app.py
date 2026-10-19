from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import jwt
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps   # 新增这一行

load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
JWT_SECRET = os.getenv("JWT_SECRET_KEY")

db = SQLAlchemy(app)

# 用户数据表
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

# JWT鉴权中间件，增加 @wraps(func) 解决名字冲突！
def token_required(func):
    @wraps(func)   # 关键修复代码
    def wrapper(*args,**kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error":"Unauthorized, missing token"}),401
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = User.query.get(payload["user_id"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error":"Token expired"}),401
        except jwt.InvalidTokenError:
            return jsonify({"error":"Invalid token"}),401
        return func(current_user,*args,**kwargs)
    return wrapper

#1 登录接口 POST /auth/login
@app.route("/auth/login",methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password_raw = data.get("password")
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password_raw.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({"message":"Wrong username or password"}),401
    #签发JWT，有效期30分钟
    token = jwt.encode({
        "user_id":user.id,
        "exp":datetime.utcnow() + timedelta(minutes=30)
    },JWT_SECRET,algorithm="HS256")
    return jsonify({"access_token":token})

#2 需要鉴权 GET /api/data
@app.route("/api/data",methods=["GET"])
@token_required
def get_data(current_user):
    #模拟返回数据，做简单转义防御XSS
    safe_name = str(current_user.username).replace("<","&lt;").replace(">","&gt;")
    result = {
        "user_name": safe_name,
        "data_list":["item1","item2","item3"]
    }
    return jsonify(result)

#3 自定义接口：获取个人信息 GET /api/user/profile
@app.route("/api/user/profile",methods=["GET"])
@token_required
def get_profile(current_user):
    safe_name = str(current_user.username).replace("<","&lt;").replace(">","&gt;")
    return jsonify({"id":current_user.id,"username":safe_name})

#初始化数据库，创建测试用户
with app.app_context():
    db.create_all()
    #创建测试用户 admin / password123!
    test_user = User.query.filter_by(username="admin").first()
    if not test_user:
        hash_pw = bcrypt.hashpw(b"password123!", bcrypt.gensalt()).decode("utf-8")
        new_user = User(username="admin",password_hash=hash_pw)
        db.session.add(new_user)
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=False)
