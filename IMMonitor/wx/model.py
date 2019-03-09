#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File    : model.py
# @Time    : 2018-12-13 13:23
# @Software: PyCharm
# @Author  : Taoz
# @contact : 371956576@qq.com
# 微信相关ORM

import json
import logging

from sqlalchemy import and_

from IMMonitor.db.common import db, Base
from IMMonitor.wx import config


class WxAccount(Base):
    id = db.Column(db.Integer, primary_key=True)  # 消息id 自动递增
    uin = db.Column(db.String(80), unique=True)
    uuid = db.Column(db.String(80))
    skey = db.Column(db.String(80))
    sid = db.Column(db.String(80))

    passticket = db.Column(db.String(255))
    logintime = db.Column(db.String(255))
    deviceid = db.Column(db.String(255))
    url = db.Column(db.String(255))
    syncurl = db.Column(db.String(255))
    fileurl = db.Column(db.String(255))

    username = db.Column(db.String(80))
    nickname = db.Column(db.String(80))
    sex = db.Column(db.String(3))
    headimgurl = db.Column(db.String(255))

    remarkname = db.Column(db.String(80))
    pyinitial = db.Column(db.String(80))
    pyquanpin = db.Column(db.String(80))
    remarkpyinitial = db.Column(db.String(80))
    remarkpyquanpin = db.Column(db.String(80))
    hideinputbarflag = db.Column(db.String(10))

    starfriend = db.Column(db.String(3))
    signature = db.Column(db.String(255))
    appaccountflag = db.Column(db.String(3))
    verifyflag = db.Column(db.String(3))
    contactflag = db.Column(db.String(3))
    webwxpluginswitch = db.Column(db.String(3))
    headimgflag = db.Column(db.String(3))

    invitestartcount = db.Column(db.String(3))
    synckey = db.Column(db.String(255))
    synckeydict = db.Column(db.String(255))

    @classmethod
    def save(cls, user_dict):
        if not user_dict.get('uin'):
            return False
        account = WxAccount.query.filter_by(uin=user_dict.get('uin')).first()

        existed = True
        if not account:
            existed = False
            account = WxAccount()

        for key in user_dict.keys():
            setattr(account, key, str(user_dict[key]))

        if existed:
            try:
                db.session.commit()
                return True
            except Exception as err:
                logging.log(logging.ERROR, repr(err))
                return False
        else:
            try:
                db.session.add(account)
                db.session.commit()
                return True
            except Exception as err:
                logging.log(logging.ERROR, repr(err))
                return False


class WxGroup(Base):
    id = db.Column(db.Integer, primary_key=True, comment='自增id')  # 消息id 自动递增
    user_uin = db.Column(db.String(80), comment='用户uin')
    Uin = db.Column(db.String(80), comment='群组uin（预留，目前返回的Uin都为0）')
    UserName = db.Column(db.String(80), unique=True, nullable=False,
                         comment='微信群组的标识name（以@@开头，每次登录返回的都不一样）')
    NickName = db.Column(db.String(80), comment='群名')
    HeadImgUrl = db.Column(db.String(255))
    ContactFlag = db.Column(db.String(2))
    MemberCount = db.Column(db.String(10))

    RemarkName = db.Column(db.String(80))
    HideInputBarFlag = db.Column(db.String(3))
    Sex = db.Column(db.String(3))
    Signature = db.Column(db.String(3))
    VerifyFlag = db.Column(db.String(3))
    OwnerUin = db.Column(db.String(3))
    PYInitial = db.Column(db.String(80))
    PYQuanPin = db.Column(db.String(80))
    RemarkPYInitial = db.Column(db.String(80))
    RemarkPYQuanPin = db.Column(db.String(80))
    StarFriend = db.Column(db.String(10))
    AppAccountFlag = db.Column(db.String(3))
    Statues = db.Column(db.String(3))
    AttrStatus = db.Column(db.String(3))
    Province = db.Column(db.String(80))
    City = db.Column(db.String(80))
    Alias = db.Column(db.String(80))
    SnsFlag = db.Column(db.String(3))
    UniFriend = db.Column(db.String(10))
    DisplayName = db.Column(db.String(80))
    ChatRoomId = db.Column(db.String(80))
    KeyWord = db.Column(db.String(255))
    EncryChatRoomId = db.Column(db.String(80))
    IsOwner = db.Column(db.String(3))

    @classmethod
    def save_one(cls, group_dict, user_uin):
        """
        以群的昵称（nickname）作为唯一ID存储群组信息
        通常用在第一次登录的时候
        :param group_dict: 群组信息字典
        :param user_uin: 用户uin
        :return: bool
        """
        existed = False
        # 先用group的昵称作为唯一ID来找该群组
        # 1、通常用在登录的时候，假设退出登录到登录期间的群名没有发生变化，则继续保存该群的信息
        #    如果登录的时候，退出登录到登录期间的群名发生了变化，则只能把它作为一个新群
        # 2、也可用在登录期间，如果某种原因导致群的username发生变化但是群名没变，可以使用该方法
        group = db.session.query(cls).filter(and_(cls.NickName == group_dict['NickName'], cls.user_uin == user_uin)).first()
        if group:
            existed = True

        # 然后再以group的username作为唯一ID来找群
        # 1、由于每次登录时的username都会变，所以重新登录时用这种方法肯定找不到该群
        # 2、这里只是适用于在登录期间群名发生了变化但是群的username发生变化的情况
        if not group:
            group = db.session.query(cls).filter(
                and_(cls.UserName == group_dict['UserName'], cls.user_uin == user_uin)).first()
            if group:
                existed = True
            else:
                group = cls()
                existed = False

        for key in group_dict.keys():
            setattr(group, key, str(group_dict[key]))

        if existed:
            try:
                db.session.commit()
                return True
            except Exception as err:
                logging.log(logging.ERROR, repr(err))
                return False
        else:
            try:
                db.session.add(group)
                db.session.commit()
                return True
            except Exception as err:
                logging.log(logging.ERROR, repr(err))
                return False

    @classmethod
    def find_one(cls, user_name):
        """
        查询一个群组的信息
        :param user_name: 群组标识name @@开头
        :return: WxGroup
        """
        return cls.query.filter_by(UserName=user_name).first()


class WxGroupMember(Base):
    id = db.Column(db.Integer, primary_key=True, comment='自增id')
    user_uin = db.Column(db.String(80), comment='用户uin')
    GroupUserName = db.Column(db.String(80), comment='微信群组的标识name（以@@开头，每次登录返回的都不一样）')
    GroupNickName = db.Column(db.String(80), comment='群名')
    Uin =  db.Column(db.String(80), comment='群组uin（预留，目前返回的Uin都为0）')
    UserName = db.Column(db.String(80), comment='用户的标识name（以@开头，每次登录返回的都不一样）')
    DisplayName = db.Column(db.String(80), comment='用户在群里面显示的名称（用户自己修改）')
    NickName = db.Column(db.String(80), comment='用户昵称')
    AttrStatus = db.Column(db.String(3))
    PYInitial = db.Column(db.String(3))
    PYQuanPin = db.Column(db.String(3))
    RemarkPYInitial = db.Column(db.String(3))
    RemarkPYQuanPin = db.Column(db.String(3))
    MemberStatus = db.Column(db.String(3))
    isleave = db.Column(db.String(2))

    @classmethod
    def batch_insert(cls, groupmember_list):
        """
        批量插入群组用户
        :param groupmember_list: 群组用户数据列表
        :return:
        """
        groupmember_list_save = []
        for groupmembe in groupmember_list:
            newmember = cls()
            for key in groupmembe.keys():
                setattr(newmember, key, str(groupmembe[key]))
                groupmember_list_save.append(newmember)

        try:
            db.session.add_all(groupmember_list_save)
            db.session.commit()
            return True
        except Exception as err:
            logging.log(logging.ERROR, repr(err))
            return False

    @classmethod
    def save_by_username(cls, groupmember_dict):
        """
        以username（@开头，每次重登都不一样）作为唯一ID存储群用户
        通常用于群用户昵称更新
        :param groupmember_dict: 用户数据字典
        :return:
        """
        groupmember = cls.query.filter_by(UserName=groupmember_dict['UserName']).first()
        existed = True
        if not groupmember:
            existed = False
            groupmember = WxGroupMember()

        for key in groupmember_dict.keys():
            setattr(groupmember, key, str(groupmember_dict[key]))

        if existed:
            try:
                db.session.commit()
                return True
            except Exception as err:
                logging.log(logging.ERROR, repr(err))
                return False
        else:
            try:
                db.session.add(groupmember)
                db.session.commit()
                return True
            except Exception as err:
                logging.log(logging.ERROR, repr(err))
                return False

    @classmethod
    def find_one(cls, group_username, member_username):
        """
        查询群成员信息
        :param group_username: 群组标识username 以@@开头
        :param member_username: 成员标识username 以@开头
        :return: WxGroupMember
        """
        return cls.query.filter_by(GroupUserName=group_username, UserName=member_username).first()


class WxGroupMessage(Base):
    id = db.Column(db.Integer, primary_key=True, comment='自增id')
    user_uin = db.Column(db.String(80), comment='哪个账号的群消息')
    group_id = db.Column(db.Integer, comment='群组id')
    MsgId = db.Column(db.Integer, comment='微信返回的消息id')
<<<<<<< HEAD
    GroupNickName = db.Column(db.String(80), comment='群名')
    GroupUserName = db.Column(db.String(80)
                             , comment='群的标识name（以@@开头，每次登录返回的都不一样）')
=======

>>>>>>> 3750e9ca4cb7a61bc5e01cad24f75c34e7f1b919
    FromUserName = db.Column(db.String(80)
                             , comment='消息发送人name（@开头，每次登录返回的都不一样）')
    FromUserNickName = db.Column(db.String(80), comment='消息发送人的昵称')
    FromUserDisplayName = db.Column(db.String(80), comment='消息发送人在群里面显示的昵称')

    Type = db.Column(db.Enum(config.MSG_TEXT, config.MSG_MAP, config.MSG_IMAGE, config.MSG_AUDIO, config.MSG_VIDEO),
                     comment='消息类型')
    Content = db.Column(db.Text, comment='消息内容/音频的识别结果')
    FilePath = db.Column(db.Text, comment='音频/视频的存储地址')
    atusername = db.Column(db.String(80))

    @classmethod
    def insert(cls, msg_dict):
        message = cls()

        for key in msg_dict.keys():
            setattr(message, key, str(msg_dict[key]))

        try:
            db.session.add(message)
            db.session.commit()
            return True
        except Exception as err:
            logging.log(logging.ERROR, repr(err))
            return False

    @classmethod
    def batch_insert(cls, msg_list):
        """
        批量存储群消息数据
        :param msg_list: list 消息列表
        :return:
        """
        msg_list_save = []
        for msg in msg_list:
            newmsg = cls()
            for key in msg.keys():
                setattr(newmsg, key, str(msg[key]))
            msg_list_save.append(newmsg)

        try:
            db.session.add_all(msg_list_save)
            db.session.commit()
            return True
        except Exception as err:
            logging.log(logging.ERROR, repr(err))
            return False
