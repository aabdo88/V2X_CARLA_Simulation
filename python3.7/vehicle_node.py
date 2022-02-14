import J2735Encoders as bsm_enc
import subprocess

class node:
    def __init__(self):
        self.node_name = ''

    def receive_buffer(self, node_name, sender_bsm_message, sender_bsm_buffer, pseudo_cert, pca_cert, pca_pub):
        sender = sender_bsm_buffer.get_sender()
        senderType = sender_bsm_buffer.get_senderType()
        recipient = sender_bsm_buffer.get_recipient()
        lane = sender_bsm_buffer.get_lane()
        speed = sender_bsm_buffer.get_speed()
        accel = sender_bsm_buffer.get_accel()
        maxSpeed = sender_bsm_buffer.get_maxSpeed()
        angle = sender_bsm_buffer.get_angle()
        brakes = sender_bsm_buffer.get_brakes()
        pos = sender_bsm_buffer.get_pos()
        lane_pos = sender_bsm_buffer.get_lane_pos()
        #print('decoding ----------------')
        #print(sender_bsm_message)
        python2_command = 'C:\Python27\python.exe SCMS_verify_signed_messages.py ' + sender_bsm_message
        process = subprocess.Popen(python2_command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        Verify_and_BSM = output.decode("utf-8")
        parts = Verify_and_BSM.split(':')
        bsm_check = bool(parts[0])
        received_hex = parts[1]
        if bsm_check:
            print(node_name + " received and verified BSM successfully from " + sender)
            hex_W_spaces = bsm_enc.insert_spaces(received_hex)
            BSM_hex_2 = bsm_enc.hexDecode(hex_W_spaces)
            BSM_2 = bsm_enc.asn1Decode(BSM_hex_2)
            BSM_2 = bsm_enc.decodeJ2735BSM_XY(BSM_2, False)
            #print(BSM_2)
        else:
            print("ERROR: " + node_name + " Failed to verify BSM from " + sender)





