
from flask import Blueprint, jsonify
from sqlalchemy import and_

from IMMonitor import app
from IMMonitor.db.common import db
from IMMonitor.analysis.model import MsgDetectResult
from IMMonitor.wx.model import WxGroupMessage


ACCESS_TOKEN = '24.5066b60e5aa6af8577c4aadaec727cd8.2592000.1546587768.282335-15056684'
DETECT_URL_IMG = 'https://aip.baidubce.com/rest/2.0/solution/v1/img_censor/user_defined'
DETECT_URL_TEXT = 'https://aip.baidubce.com/rest/2.0/antispam/v2/spam'

bp_analysis = Blueprint('bp_analysis', __name__)


@app.route('/analysis/group_danger')
def group_danger():
    danger_list = db.session.query(WxGroupMessage, MsgDetectResult)\
        .filter(and_(MsgDetectResult.result_label == 13,
                     WxGroupMessage.MsgId == MsgDetectResult.msg_id)).all()
    for danger in danger_list:
        print(danger[0].GroupNickName,
              danger[0].FromUserNickName,
              danger[0].Content,
              danger[1].result_info,
              danger[1].result_label)
    return jsonify({'ok': 'ok'})