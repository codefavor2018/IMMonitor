#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : proxy.py
# @Time    : 2018-12-12 10:23
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 微信消息相关请求代理

import base64
import io
import json
import random
import re
import time
import xml

import requests
from flask import session
from pyqrcode import QRCode

from IMMonitor.wx import s, config, getBaseRequest
from IMMonitor.wx.utils import *
from IMMonitor import SESSION_KEY, ret_val
from IMMonitor.wx.model import *

try:
    from httplib import BadStatusLine
except ImportError:
    from http.client import BadStatusLine


def sync_check():
    """
    检查是否有新消息代理
    :return:
    """

    '''
    -----------------------------------------------------------------------------------------------------
    | 接口地址 | https://webpush2.weixin.qq.com/cgi-bin/mmwebwx-bin/synccheck
    -----------------------------------------------------------------------------------------------------
    | 请求方法 | GET
    -----------------------------------------------------------------------------------------------------
    |          |  r=时间戳（ms）
    |          |  skey=xxx
    |          |  sid=xxx
    | 传递参数 |  uin=xxx
    |          |  deviceid=xxx
    |          |  synckey=1_654585659%7C2_654585745%7C3_654585673%7C1000_1467162721_=1467184052133
    -----------------------------------------------------------------------------------------------------
    |  返回值  |  {window.synccheck={retcode:"xxx",selector:"xxx"}
    -----------------------------------------------------------------------------------------------------
    |          |  retcode:
    |          |    0 正常
    |          |    1100 失败/退出微信
    | 返回参数 |  selector:
    |          |    0 正常，无新消息
    |          |    2 新的消息
    |          |    4 朋友圈有动态
    |          |    6 有消息返回结果
    |          |    7 进入/离开聊天界面
    -----------------------------------------------------------------------------------------------------

    web微信主要的过程就是轮询+获取消息的循环。轮询的接口为synccheck，获取消息接口为webwxsync。
    首先向synccheck接口发起GET请求，如果暂时没有新消息的话，保持住连接不返回直至超时。

    超时后会返回一个类似这样的数据包: {window.synccheck={retcode:"xxx",selector:"xxx"}
    其中RETCODE为返回状态，非0代表有错误；
    SELECTOR代表消息，0为无消息，非0值则有消息。

    因此，对于超时的情况，selector是为0的。
    如果在GET请求后发现有新消息，那么服务器会立刻返回一个同样格式的数据包，RETCODE为0，SELECTOR不为0。
    此时，就需要调用webwxsync接口，用POST方式去获取新消息。
    POST请求的返回除了有消息以外，header里还有Set cookie指令（不过好像每次的cookie都一样而且过期时间有一天之多），
    另外response body里还有一个重要的东西，就是syncKey和syncCheckKey。
    这里就是我前文中提到的过时的情况之一，网上绝大多数资料都是只有一个syncKey，实际返回的却有一个syncKey和一个syncCheckKey。
    从名字就能看出来，前者用于synccheck接口，后者用于webwxsync接口。
    由于syncKey每次都更新，所以如果某一次webwxsync接口的响应出了意外，后面的程序是没法进行下去的（本地key已经过期了）。

    参考文档：
    1、 https://blog.csdn.net/wonxxx/article/details/51787041
    2、https://www.cnblogs.com/shawnye/p/6376400.html
    '''

    loginInfo = session.get('WxLoginInfo')
    # 组装请求url及参数
    url = '%s/synccheck' % loginInfo.get('syncUrl', loginInfo['url'])
    params = {
        'r': int(time.time() * 1000),
        'skey': loginInfo['skey'],
        'sid': loginInfo['sid'],
        'uin': loginInfo['uin'],
        'deviceid': loginInfo['deviceid'],
        'synckey': loginInfo['synckey'],
        '_': loginInfo['logintime'], }
    headers = {'User-Agent': config.USER_AGENT}
    loginInfo['logintime'] += 1
    # 同步更新session中的logintime
    session[SESSION_KEY.WxLoginInfo]['logintime'] = loginInfo['logintime']
    try:
        r = s.get(url, params=params, headers=headers, timeout=config.TIMEOUT)
    except requests.exceptions.ConnectionError as e:
        try:
            if not isinstance(e.args[0].args[1], BadStatusLine):
                raise
            # will return a package with status '0 -'
            # and value like:
            # 6f:00:8a:9c:09:74:e4:d8:e0:14:bf:96:3a:56:a0:64:1b:a4:25:5d:12:f4:31:a5:30:f1:c6:48:5f:c3:75:6a:99:93
            # seems like status of typing, but before I make further achievement code will remain like this
            return '2'
        except:
            raise
    # 如果有连接为404等异常，使用Request.raise_for_status 抛出异常
    r.raise_for_status()

    # 提取返回参数
    regx = r'window.synccheck={retcode:"(\d+)",selector:"(\d+)"}'
    pm = re.search(regx, r.text)

    # 筛选消息
    # 如果返回中的 retcode参数 == 0，返回 select的值
    # 其他即判断为出错返回None
    if pm is None or pm.group(1) != '0':
        return ret_val.gen(ret_val.CODE_PROXY_ERR,
                           extra_msg='Weixin proxy sync_check get wrong response '
                                     '微信sync_check检查消息接口返回值不正确，失败或退出微信')

    return ret_val.gen(ret_val.CODE_SUCCESS, data={
            "message_status": pm.group(2)
        })


def get_msg():
    """
    拉取新消息代理
    :param self:
    :return: tuple （dic['AddMsgList'], dic['ModContactList']）
    AddMsgList: list 所有的新消息列表
    ModContactList：list 所有联系人有变动的列表
    """

    loginInfo = session.get(SESSION_KEY.WxLoginInfo)
    # 组装获取新消息的url及参数
    url = '%s/webwxsync?sid=%s&skey=%s&pass_ticket=%s' % (
        loginInfo['url'], loginInfo['sid'],
        loginInfo['skey'], loginInfo['passticket'])
    data = {
        'BaseRequest': getBaseRequest(),
        'SyncKey': loginInfo['synckeydict'],
        'rr': ~int(time.time()), }
    headers = {
        'ContentType': 'application/json; charset=UTF-8',
        'User-Agent': config.USER_AGENT}

    # 发起拉取新消息的请求
    r = s.post(url, data=json.dumps(data), headers=headers, timeout=config.TIMEOUT)

    response = json.loads(r.content.decode('utf-8', 'replace'))
    if response['BaseResponse']['Ret'] != 0:
        return ret_val.gen(ret_val.CODE_PROXY_ERR,
                           extra_msg='Error get msg ! 拉取新消息出错 !')

    # 更新session登录信息中的synckeyresponset及synckey
    session[SESSION_KEY.WxLoginInfo]['synckeydict'] = response['SyncKey']
    session[SESSION_KEY.WxLoginInfo]['synckey'] = '|'.join(['%s_%s' % (item['Key'], item['Val'])
                                          for item in response['SyncCheckKey']['List']])

    return ret_val.gen(ret_val.CODE_SUCCESS, data={
        'AddMsgList': response['AddMsgList'],
        'ModContactList': response['ModContactList']
    })


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
    # 正则匹配判断是否为别人所发
    if r:
        # 获取真实的用户名与内容
        actualUserName, content = r.groups()
        # 聊天群组的用户名, 该出的用户名是经过编码后的用户名
        chatroomUserName = msg['FromUserName']
    # 如果信息为自己所发
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
        return

    # 检索到当前收到信息的聊天室
    group = WxGroup.find_one(user_name=chatroomUserName)
    # TODO 如果消息不是来自已监控群的处理
    if not group:
        return None
    else:
        # 群组名称
        msg['GroupUserName'] = group.UserName
        msg['GroupNickName'] = group.NickName
        # 找到发信息的成员
        member = WxGroupMember.find_one(group_username=chatroomUserName, member_username=actualUserName)
        # TODO 如果没有找到该成员的处理
        if not member:
            return None

        # 如果更新后找到发送消息成员的信息
        else:
            # 实际的昵称==成员的备注或者群昵称, 有备注显示备注, 否者显示群昵称,DisplayName群里显示的名称
            msg['ActualNickName'] =  member.NickName
            msg['ActualDisplayName'] = member.DisplayName
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
        msg['ActualUserName'] = actualUserName
        # 信息内容
        msg['Content'] = content
        # 信息格式化处理, 解决web微信的一些bug
        msg_formatter(msg, 'Content')


def send_raw_msg(msgType, content, toUserName):
    loginInfo = session.get(SESSION_KEY.WxLoginInfo)
    url = '%s/webwxsendmsg' % loginInfo['url']
    data = {
        'BaseRequest': getBaseRequest(),
        'Msg': {
            'Type': msgType,
            'Content': content,
            'FromUserName': loginInfo['username'],
            'ToUserName': toUserName,
            'LocalID': int(time.time() * 1e4),
            'ClientMsgId': int(time.time() * 1e4),
        },
        'Scene': 0, }
    headers = {'ContentType': 'application/json; charset=UTF-8', 'User-Agent': config.USER_AGENT}
    r = s.post(url, headers=headers,
                    data=json.dumps(data, ensure_ascii=False).encode('utf8'))

    response = json.loads(r.content.decode('utf-8', 'replace'))
    if response['BaseResponse']['Ret'] != 0:
        return ret_val.gen(ret_val.CODE_PROXY_ERR,
                           extra_msg='Error get msg ! 消息发送失败 !')
    else:
        return ret_val.gen(ret_val.CODE_SUCCESS)
