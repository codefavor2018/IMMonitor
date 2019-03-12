from flask import Blueprint, jsonify, request
from sqlalchemy import and_
from IMMonitor import app, ret_val
from IMMonitor.db.common import db
from IMMonitor.analysis.model import MsgDetectResult
from IMMonitor.wx.model import WxGroupMessage

ACCESS_TOKEN = '24.5066b60e5aa6af8577c4aadaec727cd8.2592000.1546587768.282335-15056684'
DETECT_URL_IMG = 'https://aip.baidubce.com/rest/2.0/solution/v1/img_censor/user_defined'
DETECT_URL_TEXT = 'https://aip.baidubce.com/rest/2.0/antispam/v2/spam'

bp_analysis = Blueprint('bp_analysis', __name__)


# 2.识别每个群违规信息关键词，绘制词云图
@app.route('/analysis/msg_keywords')
def msg_keywords():
    """
    识别并统计每个群违规信息关键词
    :return:
    """
    args = request.args
    group_id = args.get('group_id')

    if not group_id:
        return jsonify(ret_val.gen(ret_val.CODE_PARAMS_ERR, extra_msg='需要传入group_id参数'))
    # 数据库交互，取出每条违规消息敏感词列表
    keywords = db.session.query(MsgDetectResult.result_info, WxGroupMessage)\
        .filter(and_(WxGroupMessage.group_id == group_id, MsgDetectResult.msg_id == WxGroupMessage.MsgId)).all()
    keywords_list = []
    for keyword in keywords:
        keywords_list += keyword[0].split(',')
    keywords_dict = {}
    # 桶排序统计每条违规消息敏感词频数
    for key_word in keywords_list:
        if not keywords_dict.get(key_word):
            keywords_dict[key_word] = 1
        else:
            keywords_dict[key_word] = keywords_dict[key_word] + 1

    return jsonify(ret_val.gen(ret_val.CODE_SUCCESS, data=keywords_dict))


# 3.每个群成员发送违规消息量统计
@app.route('/analysis/member_danger')
def member_danger():
    """
    统计指定群成员发送违规消息量
    :return:
    """
    args = request.args
    group_id = args.get('group_id')
    if not group_id:
        return jsonify(ret_val.gen(ret_val.CODE_PARAMS_ERR, extra_msg='需要传入group_id参数'))
    # 数据库交互，取出发出每条违规消息的成员名列表
    danger_list = db.session.query(MsgDetectResult, WxGroupMessage.FromUserNickName)\
        .filter(and_(WxGroupMessage.group_id == group_id, MsgDetectResult.msg_id == WxGroupMessage.MsgId)).all()
    member_list = {}
    # 桶排序实现群成员违规消息统计
    for danger in danger_list:
        UserNickName = danger[1]
        if not member_list.get(UserNickName):
            member_list[UserNickName] = 1
        else:
            member_list[UserNickName] = member_list[UserNickName] + 1

    return jsonify(ret_val.gen(ret_val.CODE_SUCCESS, data=member_list))

# 4. 统计单个群消息总数，每种违规消息（比如暴恐，色情，政治敏感等）数量
@app.route('/analysis/group_danger')
def group_danger():
    """
     统计单个群消息总数，每种违规消息（比如暴恐，色情，政治敏感等）数量
    :return:
    """
    args = request.args
    group_id = args.get('group_id')
    if not group_id:
        return jsonify(ret_val.gen(ret_val.CODE_PARAMS_ERR, extra_msg='需要传入group_id参数'))

    danger_list = db.session.query(WxGroupMessage, MsgDetectResult)\
        .filter(and_(WxGroupMessage.group_id == group_id,
                     WxGroupMessage.MsgId == MsgDetectResult.msg_id)).all()

    # img_type = {'1': '色情', '2': '性感', '3': '暴恐', '4': '恶心'', '8': '政治人物'}
    # text_label = {'21': '暴恐违禁', '22': '文本色情', '23': '政治敏感', '24': '恶意推广', '25': '低俗辱骂'}
    label_dict = {
        "色情性感": 0,    # 1+2+22
        "暴恐违禁": 0,    # 3+21
        "政治敏感": 0,    # 8+23
        "恶心推广": 0,    # 4+24
        "低俗辱骂": 0,    # 25
    }
    for danger in danger_list:
        danger_key = str(danger[1].result_label)
        if danger_key in ['1','2','22']:
            label_dict["色情性感"] += 1
        elif danger_key in ['3', '21']:
            label_dict["暴恐违禁"] += 1
        elif danger_key in ['8', '23']:
            label_dict["政治敏感"] += 1
        elif danger_key in ['4', '24']:
            label_dict["恶心推广"] += 1
        else:
            label_dict["低俗辱骂"] += 1
    print(label_dict)
    return jsonify(ret_val.gen(ret_val.CODE_SUCCESS, data=label_dict))


# 5.单个群每天各时段违规消息占比变化趋势图
@app.route('/analysis/date_danger')
def date_danger():
    """
    单个群每天各时段违规消息占比变化趋势图
    :return:
    {
    "2019-03-08": {
      "10": 2,
      "11": 2
    },
    "2019-03-09": {
      "11": 2,
      "12": 2,
      "13": 1
    }
    """
    args = request.args
    group_id = args.get('group_id')
    if not group_id:
        return jsonify(ret_val.gen(ret_val.CODE_PARAMS_ERR, extra_msg='需要传入group_id参数'))

    data_list = db.session.query(MsgDetectResult.date_created)\
        .filter(and_(WxGroupMessage.group_id == group_id,
                     WxGroupMessage.MsgId == MsgDetectResult.msg_id)).all()
    danger_hour_dict = {}
    date_dict = {}
    for date in data_list:
        danger_hour = date[0].strftime("%Y-%m-%d %H")
        danger_hour_dict[danger_hour] = danger_hour_dict.get(danger_hour, 0) + 1
    for key, value in danger_hour_dict.items():
        if " " in key:
            parts = key.split(" ")
            par = date_dict
            key = parts.pop(0)
            while parts:
                par = par.setdefault(key, {})
                key = parts.pop(0)
                par[key] = value
        else:
            date_dict[key] = value
    return jsonify(ret_val.gen(ret_val.CODE_SUCCESS, data=date_dict))
