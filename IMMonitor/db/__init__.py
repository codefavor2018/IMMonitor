#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : __init__.py.py
# @Time    : 2019-3-3 21:20
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 数据库初始化信息

from IMMonitor.user.model import *
from IMMonitor.wx.model import *
from IMMonitor.analysis.model import MsgDetectResult
from IMMonitor.db.common import app, db

def init_database():
    """
    初始化数据库
    :return:
    """
    db.init_app(app)
    db.create_all()

def init_testuser():
    """
    初始化测试用户
    :return:
    """
    for username in ['wx_001', 'wx_002']:
        if not User.query.filter_by(username=username).first():
            db.session.add(User(username=username))
            db.session.commit()