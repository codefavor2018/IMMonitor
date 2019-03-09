#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : __init__.py
# @Time    : 2018-12-11 18:11
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# flask 入口定义

from flask import Flask, render_template, request, session, g
from flask_login import LoginManager, login_required, login_user, logout_user


async_mode = None
app = Flask(__name__)
app.config['SECRET_KEY'] = 'IMMoniterSecrectKey'

from IMMonitor.db import db, app, init_database, init_testuser

# 用户登录模块配置
login_manager = LoginManager()
login_manager.session_protection = 'strong'  # 设置登录安全级别
login_manager.login_view = 'login'  # 指定了未登录时跳转的页面
login_manager.init_app(app)


from IMMonitor.index import bp_index
app.register_blueprint(bp_index)

from IMMonitor.user.controller import ctrl_user_bp
app.register_blueprint(ctrl_user_bp)

from IMMonitor.wx.login import bp_wx_login
app.register_blueprint(bp_wx_login)
from IMMonitor.wx.message import bp_wx_message
app.register_blueprint(bp_wx_message)
from IMMonitor.wx.contact import bp_wx_contact
app.register_blueprint(bp_wx_contact)
from IMMonitor.analysis import bp_analysis
app.register_blueprint(bp_analysis)

def initialize():
    init_database()
    init_testuser()