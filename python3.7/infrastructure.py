from Draw_rsu import pygame_rsu
from RSU import control

class communications_service:
    def __init__(self):
        self.type = ''

    def V2V(self, cvs):
        self.type = 'V2V'
        for sender_cv in cvs:
            for receiver_cv in cvs:
                if sender_cv.name != receiver_cv.name:
                    Inside_Range_status = sender_cv.pygame_car.CV_range_intersects(receiver_cv.pygame_car)
                    if Inside_Range_status:
                        sender_bsm_message, sender_bsm_buffer, sender_pseudo_cert, sender_pca_cert, sender_pca_pub = sender_cv.sender_message()
                        receiver_cv.receive(sender_bsm_message, sender_bsm_buffer, sender_pseudo_cert, sender_pca_cert, sender_pca_pub)

    def V2I(self, rsus, cvs):
        self.type = 'V2I'
        rsu_unit = pygame_rsu()
        for rsu in rsus:
            for sender_cv in cvs:
                Inside_Range_status = rsu_unit.RSU_range_intersects(rsu, sender_cv.pygame_car)
                if Inside_Range_status:
                    sender_bsm_message, sender_bsm_buffer, sender_pseudo_cert, sender_pca_cert, sender_pca_pub = sender_cv.sender_message()
                    control.receive_buffer(rsu, sender_bsm_message, sender_bsm_buffer, sender_pseudo_cert, sender_pca_cert, sender_pca_pub)


