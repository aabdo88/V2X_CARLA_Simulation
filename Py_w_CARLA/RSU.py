import J2735Encoders as bsm_enc
import scsm

class control:
    def __init__(self):
        self.node_name = ''

    def receive_buffer(self, rsu, sender_bsm_message, sender_bsm_buffer, pseudo_cert, pca_cert, pca_pub):
        self.node_name = rsu['name']
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
        OBU = scsm.OBU()
        #print('decoding ----------------')
        bsm_check, received_hex = OBU.verify_signed_messages(sender_bsm_message, pseudo_cert, pca_cert, pca_pub)
        if bsm_check:
            print (self.node_name + " received and verified BSM successfully from " + sender)
            hex_W_spaces = bsm_enc.insert_spaces(received_hex)
            #print(hex_W_spaces)
            BSM_hex_2 = bsm_enc.hexDecode(hex_W_spaces)
            BSM_2 = bsm_enc.asn1Decode(BSM_hex_2)
            BSM_2 = bsm_enc.decodeJ2735BSM_XY(BSM_2, False)
            #print(BSM_2)
        else:
            print("ERROR: " + self.node_name + " Failed to verify BSM from " + sender)
