#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : ret_val.py
# @Time    : 2019-3-3 17:56
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 定义返回值


CODE_SUCCESS = 200
CODE_PROXY_ERR = 424
CODE_PARAMS_ERR = 400
CODE_INNER_ERR = 500
CODE_SOCKET_ERR = 1001



def gen(code, data={}, extra_msg=''):
    """
    生成返回值
    :param code: integer 返回代码
    :param extra_msg: 额外返回的信息
    :param data: 返回的数据
    :return:
    """

    code_trans = {
        200: '成功',
        424: '请求代理发生错误',
        400: '请求参数有误',
        500: '服务器内部错误',
        1001: 'WebSocket连接错误'
    }

    ret_msg = '%s ! %s' % (code_trans[code], extra_msg) if extra_msg else code_trans[code]
    if data:
        return {
            'code': code,
            'msg': ret_msg,
            'data': data
        }
    else:
        return {
            'code': code,
            'msg': ret_msg,
        }
