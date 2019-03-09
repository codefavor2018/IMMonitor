
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


@app.route('/analysis/group_danger')
def group_danger():
    args = request.args
    group_username = args.get('group_username')
    if not group_username:
        return jsonify(ret_val.gen(ret_val.CODE_PARAMS_ERR, extra_msg='需要传入group_username参数'))

    danger_list = db.session.query(WxGroupMessage, MsgDetectResult)\
        .filter(and_(WxGroupMessage.GroupUserName == group_username,
                     WxGroupMessage.MsgId == MsgDetectResult.msg_id)).all()
    label_dict = {
        '1': 0,
        '2': 0,
        '3': 0,
        '4': 0,
    }
    for danger in danger_list:
        label_dict[str(danger[1].result_label)] += 1

    return jsonify(ret_val.gen(ret_val.CODE_SUCCESS, data=label_dict))