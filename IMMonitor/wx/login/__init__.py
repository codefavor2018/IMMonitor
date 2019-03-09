#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : __init__.py
# @Time    : 2018-12-12 12:01
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 微信登录相关路由

from IMMonitor import app
from IMMonitor.wx.login import proxy
from flask import jsonify, Blueprint, session
from IMMonitor.wx.model import WxAccount
from IMMonitor import SESSION_KEY

bp_wx_login = Blueprint('bp_wx_login', __name__)

@app.route('/wx/login/qrcode')
def qrcode():
    ret = proxy.get_QR()
    return jsonify(ret)

@app.route('/wx/login/checklogin')
def checklogin():
    ret = proxy.check_login()
    return jsonify(ret)

@app.route('/wx/login/init')
def init():
    proxy_ret = proxy.web_init()
    if proxy_ret is None or proxy_ret.get('code') != 200:
        return jsonify(proxy_ret)
    else:
        user_dict = proxy_ret.get('data').get('user_dict')
        user_dict.update(session.get(SESSION_KEY.WxLoginInfo))
        for key in ['synckey', 'synckeydict', 'skey', 'invitestartcount', 'username']:
            session[SESSION_KEY.WxLoginInfo][key] = user_dict[key]

        try:
            WxAccount.save(user_dict)
            return jsonify({
                "code": 200,
                "status": "ok",
                "data": {
                    'uin': user_dict['uin'],
                    'UserName': user_dict['username'],
                    'NickName': user_dict['nickname'],
                }
            })
        except Exception:
            return jsonify({
                "code": 500,
                "status": "error",
                "msg": "Error when save Weixin Account in db ! 数据库保存微信账户信息时出错"
            })