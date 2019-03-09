#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : utils.py
# @Time    : 2019-3-4 15:25
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 消息处理的工具集
import io
import os
import re
import copy

from flask import session

from IMMonitor import SESSION_KEY
from IMMonitor.wx.model import *
from IMMonitor.wx.utils import msg_formatter
from IMMonitor.wx import config
from IMMonitor.wx import *
from IMMonitor.analysis import msg_detect


def download_fn(loginInfo, url, msgId):
    """
    下载图片及音频消息
    :param loginInfo: 登录信息
    :param url: 下载地址
    :param msgId: 消息id
    :return: 二进制流
    """
    params = {
        'msgid': msgId,
        'skey': loginInfo['skey'], }
    headers = {'User-Agent': config.USER_AGENT}
    r = s.get(url, params=params, stream=True, headers=headers)
    tempStorage = io.BytesIO()
    for block in r.iter_content(1024):
        tempStorage.write(block)
    return tempStorage.getvalue()


def produce_group_chat(msg, loginInfo):
    """
    功能: 群组聊天信息处理，添加群组及发送人信息
    :param msg: 待处理的信息
    :param loginInfo: 当前登录用户的信息
    :return: None, 因为是直接在源数据中更改内容
    """
    """
    别人发的信息格式：
    msg['Content'] = @0b4c38ff87f1d8f06556f62e1266ed67be471b761396aac2a9e967cd7c2858a7:<br/>打工的怪不得
    自己发的信息格式：
    msg['Content'] = 打工的怪不得
    """
    # 正则表达式，匹配第一个@后的0-9或者a-z字符，以及<br/>后的除换行后的任意字符
    r = re.match('(@[0-9a-z]*?):<br/>(.*)$', msg['Content'])

    '''
    接下来的3个判断语句用于提取
    actualUserName：信息发送人的username
    chatroomUserName：群的username
    '''

    chatroomUserName = ''
    # 消息为别人所发
    if r:
        # 获取真实的用户名与内容
        actualUserName, content = r.groups()
        # 聊天群组的用户名, 该出的用户名是经过编码后的用户名
        chatroomUserName = msg['FromUserName']

    # 消息为自己所发
    elif msg['FromUserName'] == loginInfo['username']:
        # 真实的用户名等于自己的用户名
        actualUserName = loginInfo['username']
        # 消息的内容
        content = msg['Content']
        # 聊天群组用户名等于msg中接受者的用户名
        chatroomUserName = msg['ToUserName']
    # 该种情况为明, 大致可以用于处理微信的表情的debug
    else:
        # 实际的用户名
        msg['ActualUserName'] = loginInfo['username']
        # 信息的别名
        msg['ActualNickName'] = loginInfo['username']

        # 有没有@符号
        msg['IsAt'] = False
        # 处理表情的bug, 如微信后台引起的关于emoji匹配的bug, 脸上欢乐的泪水将被替换为猫脸上欢乐的泪水
        msg_formatter(msg, 'Content')

    # 检索到当前收到信息的聊天室
    group = WxGroup.find_one(user_name=chatroomUserName)
    print('find group: ', group)
    # TODO 如果消息不是来自已监控群的处理
    if not group:
        return
    else:
        # 群组名称
        msg['group_id'] = group.id
        # 找到发信息的成员
        member = WxGroupMember.find_one(group_username=chatroomUserName, member_username=actualUserName)

        # TODO 如果没有找到该成员的处理
        if not member:

            return


        # 如果更新后找到发送消息成员的信息
        else:
            # 实际的昵称==成员的备注或者群昵称, 有备注显示备注, 否者显示群昵称,DisplayName群里显示的名称
            msg['FromUserNickName'] =  member.NickName
            msg['FromUserDisplayName'] = member.DisplayName
            # 拼接@标志位，格式为@+登录用户在群里的显示名称

            # TODO 有消息at我时候的处理
            # for memb in chatroom['MemberList']:
            #     if memb['UserName'] == loginInfo['User']['UserName']:
            #         break
            # atFlag = '@' + (memb.get('DisplayName', '') or loginInfo['User']['NickName'])
            # """
            # (atFlag + (u'\u2005' if u'\u2005' in msg['Content'] else ' ')
            # 表示为：
            # atFlag + 空格(如果存在内容中存在Unicode的空格,则为Unicode的空格, 否则英文的空格, 记为temp
            # 如果消息内容中存在temp字符串或者以temp字符串结尾,则msg['IsAt']=True, 否者为False
            # msg['IsAt']表示自己@自己时为True, 否者为False
            # """
            # msg['IsAt'] = (
            #     (atFlag + (u'\u2005' if u'\u2005' in msg['Content'] else ' '))
            #     in msg['Content'] or msg['Content'].endswith(atFlag))
        # 信息的真实用户名
        msg['FromUserName'] = actualUserName
        # 信息内容
        msg['Content'] = content
        # 信息格式化处理, 解决web微信的一些bug
        msg_formatter(msg, 'Content')
        return True


def merge_msg(msg, msg_all, user_uin):
    """
    从微信返回的所有信息中提取出需要存储的信息
    合并至已有的msg字典
    :param msg: 已有的msg字典（包含Type Content）
    :param msg_all: 微信返回的所有信息
    :param user_uin: 微信用户的uin
    :return:
    """
    new_msg = copy.deepcopy(msg)
    new_msg['user_uin'] = user_uin
    new_msg['MsgId'] = msg_all['MsgId']
    new_msg['group_id'] = msg_all['group_id']
    new_msg['FromUserName'] = msg_all['FromUserName']
    new_msg['FromUserNickName'] = msg_all['FromUserNickName']
    new_msg['FromUserDisplayName'] = msg_all['FromUserDisplayName']
    return new_msg


def produce_group_msg(msgList):
    """
    处理群消息
    :param msgList:
    :return: dict
        ret_msg_list = {
            'msg_list': [],  # 所有的消息列表
            'msg_list_detected': [],  # 检测出有问题的消息列表
        }
    """
    loginInfo = session.get(SESSION_KEY.WxLoginInfo)

    # 消息列表
    ret_msg_list = {
        'msg_list': [],  # 所有的消息列表
        'msg_list_detected': [],  # 检测出有问题的消息列表
    }
    # 无用消息类型列表码
    srl = [40, 43, 50, 52, 53, 9999]

    # 遍历消息列表
    for m in msgList:

        # 判断信息是否来自群组, 群组信息存在@@标志位
        if '@@' in m['FromUserName'] or '@@' in m['ToUserName']:
            # 群组处理信息, 判断信息别人发送还是自己发送, 填写关键信息
            # TODO 这里只对添加了通讯录的做了处理
            status = produce_group_chat(m, loginInfo)
            if not status:
                continue
        # 消息来自非群组, 跳过循环
        else:
            continue


        # # 如果信息发送人为自己
        # if m['FromUserName'] == loginInfo['username']:
        #     # 实际接收人 为 我发出的那段信息的 接收人
        #     actualOpposite = m['ToUserName']
        # # 如果信息发送人不是我自己
        # else:
        #     # 实际接收人 为 信息的发送人
        #     actualOpposite = m['FromUserName']


        # 地图或者文本信息
        if m['MsgType'] == 1:
            # 如果m['Url']存在,表示为地图
            if m['Url']:
                # 正则表达式, 匹配括号前与括号内的内容,
                # 因为地图信息格式为：贵阳科技大厦（贵阳市观山湖区八音路2号）+url格式的地图地址
                # 目前存在不能接受显示地图信息
                regx = r'(.+?\(.+?\))'
                data = re.search(regx, m['Content'])
                # 如果内容不存在, data为Map否者为正则匹配到的内容
                data = 'Map' if data is None else data.group(1)
                msg = {
                    'Type': 'Map',
                    'Content': data, }

            # 常规文本信息
            else:
                content = m['Content']
                msg = {
                    'Type': config.MSG_TEXT,
                    'Content': content, }

                msg_forsave = merge_msg(msg=msg, msg_all=m, user_uin=loginInfo['uin'])
                ret_msg_list['msg_list'].append(msg_forsave)

                # 文本检测
                detect_result = msg_detect.detect_text(content)
                unify_result_list = msg_detect.unify_detect_result(config.MSG_TEXT, m['MsgId'], detect_result)
                for unify_detect_result in unify_result_list:
                    ret_msg_list['msg_list_detected'].append(unify_detect_result)

        # 图片或者动画表情
        elif m['MsgType'] == 3 or m['MsgType'] == 47:
            # 从远处下载图像或者表情
            bite_val = download_fn(loginInfo=loginInfo,
                              url='%s/webwxgetmsgimg' % loginInfo['url'],
                              msgId=m['NewMsgId'])
            filedir = 'IMMonitor/static/wxmsg/image/'
            file_format = '.png' if m['MsgType'] == 3 else '.gif'
            filename = '{filedir}{filename}{file_format}'.format(filedir=filedir,
                                                                 filename=m['NewMsgId'],
                                                                 file_format=file_format)

            # 存储文件
            with open(filename, 'wb') as f:
                f.write(bite_val)

            msg = {
                'Type': config.MSG_IMAGE,
                'FilePath': filename.replace('IMMonitor', '')  # 图片地址
            }

            msg_forsave = merge_msg(msg=msg, msg_all=m, user_uin=loginInfo['uin'])
            ret_msg_list['msg_list'].append(msg_forsave)

            # 图片审查
            detect_result = msg_detect.detect_image(bite_image=bite_val)
            unify_result_list = msg_detect.unify_detect_result(config.MSG_IMAGE, m['MsgId'], detect_result)
            for unify_detect_result in unify_result_list:
                ret_msg_list['msg_list_detected'].append(unify_detect_result)

        # 音频
        elif m['MsgType'] == 34: # voice
            bite_val = download_fn(loginInfo=loginInfo,
                                   url='%s/webwxgetvoice' % loginInfo['url'],
                                   msgId=m['NewMsgId'])

            filedir = 'IMMonitor/static/wxmsg/audio/'
            file_format = '.wav'
            filename = '{filedir}{filename}{file_format}'.format(filedir=filedir,
                                                                 filename=m['NewMsgId'],
                                                                 file_format=file_format)
            # 存储文件
            with open(filename, 'wb') as f:
                f.write(bite_val)

            msg = {
                'Type': config.MSG_AUDIO,
                'FilePath': filename.replace('IMMonitor', ''),
                'Content': ''  # 音频的识别结果
            }

            msg_forsave = merge_msg(msg=msg, msg_all=m, user_uin=loginInfo['uin'])
            ret_msg_list['msg_list'].append(msg_forsave)

            # 文本检测
            # detect_result_list = msg_detect.detect_text(content)
            # detect_result_list = msg_detect.unify_detect_result(config.MSG_TEXT, m['MsgId'], detect_result_list)
            # for detect_result in detect_result_list:
            #     ret_msg_list['msg_list_detected'].append(detect_result)

    print(ret_msg_list)
    return ret_msg_list
