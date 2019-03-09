from IMMonitor.db.common import app, db
from IMMonitor.analysis.model import MsgDetectResult
from IMMonitor.wx.model import WxGroupMember,WxGroupMessage

# 每个群成员发送违规消息量统计
def count_outline_mes_list(group_nicknime):
    list = db.session.query(WxGroupMessage).filter_by(GroupNickName=group_nicknime).all