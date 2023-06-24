# -*- coding: utf-8 -*-
from ChangYedPY import *
from ChangYedad.ttypes import *
line = LINE(idOrAuthToken='Ft9e3QReZB5i0oMQ9lS1.nDTOvWGvwK8dZoNi4xMCqq.wP1qGgy3y58cM7nJQ4kk26yWBWW9j1Vv61YxTmO/yQI=',APP_NAME="DESKTOPWIN\t5.21.3\tWindows\t10")
line.log("Auth Token : " + str(line.authToken))
#line.log("Timeline Token : " + str(line.tl.channelAccessToken))

# Initialize OEPoll with LINE instance
oepoll = OEPoll(line)

# Receive messages from OEPoll
def RECEIVE_MESSAGE(op):
    print(op)
    msg = op.message
    text = msg.text
    msg_id = msg.id
    receiver = msg.to
    sender = msg._from
    
    try:
        # Check content only text message
        if msg.contentType == 0:
            # Check only group chat
            if msg.toType == 2:
                # Chat checked request
                line.sendChatChecked(receiver, msg_id)
                # Get sender contact
                contact = line.getContact(sender)
                # Command list
                if text.lower() == 'hi':
                    line.log('[%s] %s' % (contact.displayName, text))
                    line.sendMessage(receiver, 'Hi too! How are you?')
                elif text.lower() == '/author':
                    line.log('[%s] %s' % (contact.displayName, text))
                    line.sendMessage(receiver, 'My author is linepy')
    except Exception as e:
        line.log("[RECEIVE_MESSAGE] ERROR : " + str(e))
    
# Auto join if BOT invited to group
def NOTIFIED_INVITE_INTO_GROUP(op):
    try:
        group_id=op.param1
        # Accept group invitation
        line.acceptGroupInvitation(group_id)
    except Exception as e:
        line.log("[NOTIFIED_INVITE_INTO_GROUP] ERROR : " + str(e))

# Add function to OEPoll
oepoll.addOpInterruptWithDict({
    OpType.RECEIVE_MESSAGE: RECEIVE_MESSAGE,
    OpType.NOTIFIED_INVITE_INTO_GROUP: NOTIFIED_INVITE_INTO_GROUP
})

while True:
    oepoll.trace()