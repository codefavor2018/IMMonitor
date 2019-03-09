#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : __init__.py
# @Time    : 2018-12-12 10:05
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 微信消息相关路由

from IMMonitor import app, ret_val
from IMMonitor.wx.message import proxy, utils
from flask import jsonify, Blueprint, request
from IMMonitor.wx.model import *
from IMMonitor.wx.contact.utils import groups_from_contacts, update_group_contact_list
from IMMonitor.analysis.model import MsgDetectResult

bp_wx_message = Blueprint('bp_wx_message', __name__)
@app.route('/wx/message/sync_check')
def sync_chech():
    ret = proxy.sync_check()
    return jsonify(ret)

@app.route('/wx/message/get_msg')
def get_msg():
    # 从代理拉取新消息
    ret = proxy.get_msg()
    if ret['code'] == ret_val.CODE_SUCCESS:
        # 消息列表
        AddMsgList = ret['data']['AddMsgList']
        group_msg_list = []
        if AddMsgList:
            group_msg_list = utils.produce_group_msg(AddMsgList)
            WxGroupMessage.batch_insert(group_msg_list['msg_list'])
            if group_msg_list['msg_list_detected']:
                MsgDetectResult.batch_insert(group_msg_list['msg_list_detected'])

        # 联系人变动列表
        ModContactList = ret['data']['ModContactList']
        mod_group_list = groups_from_contacts(ModContactList)
        print(mod_group_list)
        # 因为处于已登录状态，所以更新联系人以username（@@）作为唯一ID
        update_group_contact_list(mod_group_list)

        return jsonify(ret_val.gen(ret_val.CODE_SUCCESS,
                                   data={
                                       'group_msg_list': group_msg_list,
                                       'mod_group_list': mod_group_list
                                   }))
    else:
        return jsonify(ret)


@app.route('/wx/message/send_msg')
def send_raw_msg():
    """
    发送消息, 目前只支持文字
    TODO: 支持发送图片、语音、视频等
    :return:
    """
    content = request.args.get('content')
    to_username = request.args.get('to_username')
    if not content or not to_username:
        return jsonify(ret_val.gen(ret_val.CODE_PARAMS_ERR, extra_msg='需要传入 content, to_username 参数'))

    ret = proxy.send_raw_msg(1, content=content, toUserName=to_username)
    return jsonify(ret)