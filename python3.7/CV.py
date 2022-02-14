from BSM import BSMdata
from vehicle_node import node
from Draw_car import pygame_car
import traci
import J2735Encoders as bsm_enc
import subprocess


class Connect_Vehicle:
    def __init__(self):
        self.name = ''
        self.pygame_car = pygame_car()
        self.sender_bsm_buffer = BSMdata()
        self.sender_bsm_message = ""
        self.sender_bsm_message_length = 0
        self.received_buffer = node()
        self.pseudo_cert = """
            8003 0080 fabd 443d bf85 85fa 5981 1676
            3278 7063 612d 7465 7374 2e67 6873 6973
            732e 636f 6d5e 6f5b 0002 18f3 4861 8600
            0a83 0103 8000 7c80 01e4 8003 4801 0180
            0123 8003 8500 0101 0100 8001 0200 0120
            0001 2600 8082 42ac 6bc3 42c4 93d2 a6a8
            2169 fc25 2ebf 6c86 ba6a 3285 b143 2376
            1a43 de15 ff80 8080 827c 5c5a d2e4 4129
            9c7e 87cd 60f4 05dd 4de6 8e46 e7ed 1239
            dd9e 8e39 188f a57f ef80 8000 e93d b970
            f630 d6f5 c4f0 a9e2 7a57 85f1 43e3 e82f
            9090 a76a 882f 08c6 3f79 51ec b93a c48b
            4f5b 6aac b052 35c8 230b 5c2a b624 f0df
            36cb f0f0 2f33 01b9 cf5f 69
            """.replace("\n","").replace(" ", "")
        self.pca_cert = """
                                  7c 5c5a d2e4 4129
            9c7e 87cd 60f4 05dd 4de6 8e46 e7ed 1239
            dd9e 8e39 188f a57f ef
            """.replace("\n","").replace(" ", "")
        self.pca_pub = """
            0003 0180 da76 6b0e 278f d23d 5080 8000
            7a8e 4d44 3b14 03b3 9ffc 0000 000f 8e4d
            443b 1403 b39f fc5e 6f5b 0001 191e 2210
            8400 a983 0103 8000 7c80 01e4 8003 4801
            0200 0120 0001 2681 837a 06e6 dab3 cb6c
            c0b3 7657 1681 7212 3854 690a de9a d8e7
            f1aa 9286 6fc6 c7bd 79
            """.replace("\n","").replace(" ", "")

    def read_and_send_parameters(self, veh_name, veh_specs, skip_char, Encrypt_status):
        self.name = veh_name
        self.pygame_car.copy(veh_specs)
        self.sender_bsm_buffer.set_sender(veh_name)
        self.sender_bsm_buffer.set_senderType('passenger')
        self.sender_bsm_buffer.set_recipient('broadcast')
        self.sender_bsm_buffer.set_lane(traci.vehicle.getLaneID(veh_name))
        speed = traci.vehicle.getSpeed(veh_name)
        accel = traci.vehicle.getAccel(veh_name)
        angle = traci.vehicle.getAngle(veh_name)
        self.sender_bsm_buffer.set_speed(speed)
        self.sender_bsm_buffer.set_accel(accel)
        self.sender_bsm_buffer.set_maxSpeed(traci.vehicle.getMaxSpeed(veh_name))
        self.sender_bsm_buffer.set_angle(angle)
        self.sender_bsm_buffer.set_brakes(0.0)
        pos = traci.vehicle.getPosition(veh_name)
        pos_x = pos[0]
        pos_y = pos[1]
        pos_z = 0.0
        pos_margin = [pos_x, pos_y, pos_z]
        self.sender_bsm_buffer.set_pos(pos_margin)
        self.sender_bsm_buffer.set_lane_pos(traci.vehicle.getLanePosition(veh_name))
        if Encrypt_status:
            #print('encoding ----------------')
            veh_field = bsm_enc.format_name(skip_char, veh_name)
            BSM = bsm_enc.createJ2735BSM_XY(veh_field, pos_x, pos_y, speed, accel, angle)
            print("BSM message creates by (" + veh_name + ")")
            #print(BSM.prettyPrint())
            hex = bsm_enc.hexdump2(BSM.prettyPrint())
            #hex = bsm_enc.hexdump(BSM.prettyPrint())
            #print(hex)
            hex_WO_spaces = bsm_enc.remove_spaces(hex)
            #print('hex_WO_spaces lenght = ', len(hex_WO_spaces))
            #print(hex_WO_spaces)
            #python2_command = 'C:\pypy2.7-v7.3.3-win32\pypy.exe SCMS_sign_message.py ' + str(hex_WO_spaces)
            python2_command = 'C:\Python27\python.exe SCMS_sign_message.py ' + str(hex_WO_spaces)
            process = subprocess.Popen(python2_command.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
            BSM_sighned = output.decode("utf-8")
            #print(BSM_sighned)
            self.sender_bsm_message_length = len(BSM_sighned)
            self.sender_bsm_message = BSM_sighned
            print("BSM message signed and sent by (" + veh_name + ")")
            #print("BSM message signed and sent by (" + veh_name + "): " + BSM_sighned)


    def get_parameters(self):
        cv = {
            "name": self.name,
            "pygame_car": self.pygame_car,
            "sent_bsm_buffer": self.sender_bsm_buffer,
            "bsm_message": self.sender_bsm_message
        }
        return cv

    def receive(self, sender_bsm_message, sender_bsm_buffer, sender_pseudo_cert, sender_pca_cert, sender_pca_pub):
        self.received_buffer.receive_buffer(self.name, sender_bsm_message, sender_bsm_buffer, sender_pseudo_cert, sender_pca_cert, sender_pca_pub)
    def sender_message(self):
        return self.sender_bsm_message, self.sender_bsm_buffer, self.pseudo_cert, self.pca_cert, self.pca_pub

    def get_bsm_message(self):
        return self.sender_bsm_message

