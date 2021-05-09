import json
import os
import time
import random
import string
import base64
# 创建订单
import requests
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256



class ToSign:
    timestamp = "%.f" % time.time()  # "%.f" % time.time()  # 时间戳
    nonce_str = "".join(random.sample(string.ascii_letters + string.digits, 16))  # 随机字符串

    @classmethod
    def set_sign_data(cls, method: str, url: str, body: dict):
        """设置默认数据 """
        cls.method = method
        cls.url = url
        cls.body = json.dumps(body) # 转换为json字符串

    @classmethod
    def sign_str(cls):
        """生成欲签名字符串"""
        return str("\n".join([cls.method, cls.url,
                              cls.timestamp, cls.nonce_str,
                              cls.body])+"\n")

    @classmethod
    def sign(cls, sign_str):
        """签名 """
        with open("apiclient_key.pem", 'r') as f:
            private_key = f.read()
        pkey = RSA.importKey(private_key)
        h = SHA256.new(sign_str.encode('utf-8'))
        signature = PKCS1_v1_5.new(pkey).sign(h)
        sign = base64.b64encode(signature).decode()
        return sign

    @classmethod
    def authorization_str(cls):
        sign_ = cls.sign(cls.sign_str())
        """拼接header authorization"""
        authorization = 'WECHATPAY2-SHA256-RSA2048 ' \
                        'mchid="{mchid}",' \
                        'nonce_str="{nonce_str}",' \
                        'signature="{sign}",' \
                        'timestamp="{timestamp}",' \
                        'serial_no="{serial_no}"'. \
            format(mchid="1609191198",
                   nonce_str=cls.nonce_str,
                   sign=sign_,
                   timestamp=cls.timestamp,
                   serial_no="serial_no"
                   )
        return authorization

if __name__ == "__main__":
    url = "https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi"
    data = {
        "appid": "wx36c9d622d2dcd482", #config.appid,
        "mchid": "1609191198", #"#config.mchid,
        "description": "izdax输入法，商户入驻",
        "out_trade_no": "2021050814839736",
        "notify_url": "https://weixin.qq.com/",
        "amount": {"total": 100, "currency": "CNY"},
        "payer": {"openid": "osR775SEl7mP7KaXGE-zjy_QvRlc"},
    }
    ToSign.set_sign_data("POST", "/v3/pay/transactions/jsapi", data)

    authorization_str = ToSign.authorization_str()
    headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": authorization_str
               }
    # res_data = requests.post(url, json=data, headers=headers)
    res_data = requests.post(url, json=data, headers=headers)
    print(res_data.json())