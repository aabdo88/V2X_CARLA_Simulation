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

    def read_and_send_parameters(self, veh_name, veh_specs, skip_char):
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

        #print('encoding ----------------')
        veh_field = bsm_enc.format_name(skip_char, veh_name)
        BSM = bsm_enc.createJ2735BSM_XY(veh_field, pos_x, pos_y, speed, accel, angle)
        print("BSM message creates by (" + veh_name + ")")
        #print(BSM.prettyPrint())
        hex = bsm_enc.hexdump(BSM.prettyPrint())
        #hex = bsm_enc.hexdump_with_index(BSM.prettyPrint())
        #print(hex)
        hex_WO_spaces = bsm_enc.remove_spaces(hex)
        #print('hex_WO_spaces lenght = ', len(hex_WO_spaces))
        #print(hex_WO_spaces)
        python2_command = 'C:\Python27\python.exe SCMS_sign_message.py ' + hex_WO_spaces
        process = subprocess.Popen(python2_command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        sign_message_outputs = output.split(':')
        BSM_sighned = sign_message_outputs[0]
        pseudo_cert = sign_message_outputs[1] 
        pca_cert = sign_message_outputs[2] 
        pca_pub = sign_message_outputs[3] 
        self.sender_bsm_message_length = len(BSM_sighned)
        self.sender_bsm_message = BSM_sighned
        self.pseudo_cert = pseudo_cert
        self.pca_cert = pca_cert
        self.pca_pub = pca_pub
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
        #self.received_buffer.receive_buffer(self.name, sender_bsm_message, sender_bsm_buffer, sender_pseudo_cert, sender_pca_cert, sender_pca_pub)
        print('llllllllllll')
    def sender_message(self):
        return self.sender_bsm_message, self.sender_bsm_buffer, self.pseudo_cert, self.pca_cert, self.pca_pub

    def get_bsm_message(self):
        return self.sender_bsm_message

