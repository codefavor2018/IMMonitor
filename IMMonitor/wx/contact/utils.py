#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : utils.py
# @Time    : 2018-12-12 09:23
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 微信联系人相关工具函数

from flask import session
from IMMonitor.wx.utils import emoji_formatter
from IMMonitor import SESSION_KEY, db
from IMMonitor.wx.model import WxGroup, WxGroupMember
import copy


def groups_username_from_contacts(contact_list):
    """
    从联系人列表中返回群的username列表
    :param contact_list:
    :return:
    """
    groups_name = []
    for contact in contact_list:
        user_name = contact['UserName']
        if '@@' in user_name:
            groups_name.append(user_name)
    return groups_name


def groups_from_contacts(contact_list):
    """
    从联系人列表中返回群列表
    同时把群列表中的参数全部转化为小写
    :param contact_list:
    :return:
    """
    groups = []
    for contact in contact_list:
        user_name = contact['UserName']
        if '@@' in user_name:
            groups.append(contact)
    return groups



def save_group_contact_list_by_nickname(group_contact_list):
    """
    以存储群组列表
    :param group_contact_list:
        [
            {
                'Uin': 0,
                'UserName': '@@9b94b78c20eb2ec5ee564d1a85af7d8353a125090a434ba59afdf95998e5ffdb',
                'NickName': '数据小群_ALL',
                'HeadImgUrl': '/cgi-bin/mmwebwx-bin/webwxgetheadimg?seq=690212441
                            &username=@@9b94b78c20eb2ec5ee564d1a85af7d8353a125090a434ba59afdf95998e5ffdb&skey=',
                'ContactFlag': 3,
                'MemberCount': 8,
                'MemberList': [{
                      'Uin': 0,
                      'UserName': '@0cfdcbfa81ebc14c9300a048d50b41bd82169a02cbb37f46c1dc950ec577ecb2',
                      'NickName': '贵州大学黎万英',
                      'AttrStatus': 233573,
                      'PYInitial': '',
                      'PYQuanPin': '',
                      'RemarkPYInitial': '',
                      'RemarkPYQuanPin': '',
                      'MemberStatus': 0,
                      'DisplayName': '黎万英',
                      'KeyWord': ''
                    },
                    ...
                    ...
                ],
                'RemarkName': '',
                'HideInputBarFlag': 0,
            },
            ...
            ...
        ]
    :return:
    """
    user_uin = session[SESSION_KEY.WxLoginInfo]['uin']
    for group_contact in group_contact_list:

        group_contact['user_uin'] = user_uin
        emoji_formatter(group_contact, 'UserName')
        emoji_formatter(group_contact, 'NickName')

        # 这里要pop Memberlist 再存储群组信息
        # 所以先深拷贝一下，以免修改到原来的对象
        group_copy = copy.deepcopy(group_contact)
        group_copy.pop('MemberList')
        WxGroup.save_by_nickname(group_dict=group_copy)

        for group_member in group_contact['MemberList']:
            group_member['user_uin'] = user_uin
            group_member['GroupUserName'] = group_contact['UserName']
            group_member['GroupNickName'] = group_contact['NickName']
            emoji_formatter(group_member, 'UserName')
            emoji_formatter(group_member, 'NickName')

        # 每次登录时群成员的username（@开头）都会变
        # 这里首次存储的时候可以直接批量插入
        WxGroupMember.batch_insert(groupmember_list=group_contact['MemberList'])


def update_group_contact_list_by_username(group_contact_list):
    """
    以username作为唯一ID存储群组列表
    通常用于更新群组信息
    :param group_contact_list:
    :return:
    """
    user_uin = session[SESSION_KEY.WxLoginInfo]['uin']
    for group_contact in group_contact_list:

        group_contact['user_uin'] = user_uin
        emoji_formatter(group_contact, 'UserName')
        emoji_formatter(group_contact, 'NickName')

        # 这里要pop Memberlist 再存储群组信息
        # 所以先深拷贝一下，以免修改到原来的对象
        group_copy = copy.deepcopy(group_contact)
        group_copy.pop('MemberList')
        WxGroup.save_by_username(group_dict=group_copy)

        for group_member in group_contact['MemberList']:
            group_member['user_uin'] = user_uin
            group_member['GroupUserName'] = group_contact['UserName']
            group_member['GroupNickName'] = group_contact['NickName']
            emoji_formatter(group_member, 'UserName')
            emoji_formatter(group_member, 'NickName')

            # 这里因为在已登录的时候收到了更新群列表的操作
            # 以username(@)信息作为唯一ID更新群成员的时候
            WxGroupMember.save_by_username(group_member)
            print('save user %s ' % group_contact['NickName'])