# -*- coding: utf-8 -*-
from ChangYedPY import *
from ChangYedad.ttypes import *
line = LINE(authToken='FtAJkBjCGtRXN3K4c8xd.8GSDVyigkej3RJckUOECdq.Xkyx01jvWi15PSLzOJK13RM1zww9a1pzaOGP/L/41jQ=')
line.log("Auth Token : " + str(line.authToken))
line.log("Timeline Token : " + str(line.tl.channelAccessToken))

# Initialize OEPoll with LINE instance
oepoll = OEPoll(line)

# Receive messages from OEPoll
def RECEIVE_MESSAGE(op):
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