# -*- coding: utf-8 -*-
from ChangYedPY import *
from ChangYedad.ttypes import *
from Crypto.Cipher import AES
import base64, hashlib ,json
import hmac

line = LINE(idOrAuthToken='Ft9e3QReZB5i0oMQ9lS1.nDTOvWGvwK8dZoNi4xMCqq.wP1qGgy3y58cM7nJQ4kk26yWBWW9j1Vv61YxTmO/yQI=',APP_NAME="DESKTOPWIN\t5.21.3\tWindows\t10")
#line = LINE("botadd05@yahoo.com","Botline12345")
line.log("Auth Token : " + str(line.authToken))
line.log("Timeline Token : " + str(line.tl.channelAccessToken))

# Initialize OEPoll with LINE instance
oepoll = OEPoll(line)

# def get_hashed_text_with_secret_key(secret_key: str, payload: str, method = hashlib.sha256) -> str:
#     return hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), method).hexdigest()

# def get_encrypt_data(payload: str, secret_key: str, vector: str):
#     b64_payload = base64.b64encode(payload.encode("utf-8"))

#     if len(b64_payload) % 16 != 0:
#         for _ in range(16 - (len(b64_payload) % 16)):
#             b64_payload += b"_"

#     secret_key = hashlib.sha256(secret_key.encode("utf-8")).digest()
#     vector = hashlib.md5(vector.encode("utf-8")).digest()

#     aes = AES.new(secret_key, AES.MODE_CBC, vector)
#     cipher_data = aes.encrypt(b64_payload)
#     return base64.b64encode(cipher_data).decode("utf-8")

# def get_decrypt_data(b64_cipher: str, secret_key: str, vector: str):
#     cipher_data = base64.b64decode(b64_cipher.encode("utf-8"))

#     secret_key = hashlib.sha256(secret_key.encode("utf-8")).digest()
#     vector = hashlib.md5(vector.encode("utf-8")).digest()
#     aes = AES.new(secret_key, AES.MODE_CBC, vector)

#     b64_payload = aes.decrypt(cipher_data)
#     return base64.b64decode(b64_payload.partition(b"_")[0]).decode("utf-8")

# secret_key = "encrypted_mid_key"
# mid = "u35db685708155a4f03cce9c8e1799c41"
# primary_key = get_hashed_text_with_secret_key(secret_key, mid)
# print("primary key:", primary_key)

# token = "szXvOjvlmIEuPfRHR8u8joHyQRsnM2fGd7YUVWoK5sxA4NhyC4JsroAnHtYMl57//8kNaNbUVGomvs9kYt6gCY8BG+xDMoIuqvMFeduraoyR0tG9+oUSxWLZ2wQI0YsbRCzPHGkelFrXYjbbF6XEBSNcGBe/QgDJJb67158ijjFwZil231bU8/I8EWoHOWsV"
# enc_token = get_encrypt_data(token, mid, primary_key)
# print("cnook token:", enc_token)

# token = get_decrypt_data(enc_token, mid, primary_key)
# print("token:", token)
# mid = "c5b8b1cf34fcd70f34b66082b7712fa"
# token = "szXvOjvlmIEuPfRHR8u8joHyQRsnM2fGd7YUVWoK5sxA4NhyC4JsroAnHtYMl57//8kNaNbUVGomvs9kYt6gCY8BG+xDMoIuqvMFeduraoyR0tG9+oUSxWLZ2wQI0YsbRCzPHGkelFrXYjbbF6XEBSNcGBe/QgDJJb67158ijjFwZil231bU8/I8EWoHOWsV"
# secret_key = "encrypted_mid_key"
# primary_key = get_hashed_text_with_secret_key(secret_key, mid)
# Receive messages from OEPoll
def RECEIVE_MESSAGE(op):

    msg = op.message
    text = msg.text
    msg_id = msg.id
    receiver = msg.to
    sender = msg._from
    chunks = msg.chunks
    try:
        text.lower()
    except:
        pass
    print(chunks,text)
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
                
                if text == 'hi':
                    line.log('[%s] %s' % (contact.displayName, text))
                    line.sendMessage(receiver, 'Hi too! How are you?')
                elif text == '/author':
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