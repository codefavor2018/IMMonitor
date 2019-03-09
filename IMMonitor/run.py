#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : ret_val.py
# @Time    : 2019-3-3 17:56
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 系统启动入口

import os
import sys
from flask_cors import CORS

BASE_DIR = os.path.dirname(__file__)
sys.path.append(BASE_DIR)

from IMMonitor import app, initialize
from IMMonitor.socket import socketio
if __name__ == '__main__':
    initialize()
    CORS(app, resources=r'/*', supports_credentials=True)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
