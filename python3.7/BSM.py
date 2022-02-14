class BSMdata:
    def __init__(self):
        self.sender = ""
        self.senderType = ""
        self.recipient = ""
        self.SUMO_pos_x = 0
        self.SUMO_pos_y = 0
        self.SUMO_pos_z = 0
        self.SUMO_lane_pos = 0.0
        self.speed = 0
        self.accel = 0
        self.maxSpeed = 0
        self.lane = ""
        self.angle = 0
        self.brakes = 0

    def set_sender(self, sender):
        self.sender = sender
    def set_senderType(self, senderType):
        self.senderType = senderType
    def set_recipient(self, recipient):
        self.recipient = recipient
    def set_pos(self, pos):
        self.SUMO_pos_x = pos[0]
        self.SUMO_pos_y = pos[1]
        self.SUMO_pos_z = pos[2]
    def set_lane_pos(self, lane_pos):
        self.SUMO_lane_pos = lane_pos
    def set_speed(self, speed):
        self.speed = speed
    def set_accel(self, accel):
        self.accel = accel
    def set_maxSpeed(self, maxSpeed):
        self.maxSpeed = maxSpeed
    def set_lane(self, lane):
        self.lane = lane
    def set_angle(self, angle):
        self.angle = angle
    def set_brakes(self, brakes):
        self.brakes = brakes


    def get_sender(self):
        return self.sender
    def get_senderType(self):
        return self.senderType
    def get_recipient(self):
        return self.recipient
    def get_pos(self):
        return self.SUMO_pos_x, self.SUMO_pos_y, self.SUMO_pos_z
    def get_lane_pos(self):
        return self.SUMO_lane_pos
    def get_speed(self):
        return self.speed
    def get_accel(self):
        return self.accel
    def get_maxSpeed(self):
        return self.maxSpeed
    def get_lane(self):
        return self.lane
    def get_angle(self):
        return self.angle
    def get_brakes(self):
        return self.brakes

