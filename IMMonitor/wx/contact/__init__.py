#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : __init__.py
# @Time    : 2018-12-12 09:40
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 微信联系人相关路由

from IMMonitor import app, ret_val
from IMMonitor.wx.contact import proxy
from flask import jsonify, Blueprint
from IMMonitor.wx.contact.utils import groups_username_from_contacts, save_group_contact_list

bp_wx_contact = Blueprint('bp_wx_contact', __name__)


@app.route('/wx/contact/get_contact')
def get_contact():
    all_contact = proxy.get_contact()
    return jsonify(all_contact)


@app.route('/wx/contact/get_group_contact')
def get_group_contact():
    """
    获取群组数据
    :return:
    """
    # 获取所有联系人的列表
    all_contact_res = proxy.get_contact()
    if all_contact_res['code'] == 200:
        contact_list = all_contact_res['data']['contact_list']
        # contact_list  [{'Uin': 0, 'UserName': '@885aa7efdd2a35804fb0459a5b1b67f2', 'NickName': '该帐号已冻结' ......
        # if contact_list[0]['Uin'] == 0:
        #     return jsonify(ret_val.gen(ret_val.CODE_PROXY_ERR, extra_msg=contact_list[0]['NickName']))

        # 从联系人列表中提取出群列表
        group_name_list = groups_username_from_contacts(contact_list)
        # 存储群组的联系人信息
        group_contact_res = proxy.batch_get_group_contact(group_name_list)

        if group_contact_res['code'] == ret_val.CODE_SUCCESS:
            group_contact_list = group_contact_res['data']['group_contact_list']

            save_group_contact_list(group_contact_list)
            return jsonify(ret_val.gen(ret_val.CODE_SUCCESS,
                                       data=group_contact_list,
                                       extra_msg='提取群组信息成功'))
        else:
            return jsonify(group_contact_res)
    else:
        return jsonify(all_contact_res)


