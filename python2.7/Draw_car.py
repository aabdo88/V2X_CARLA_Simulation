import pygame

#grass = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/grass.jpg'
#yellow_strip = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/yellow_strip.jpg'
#strip = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/strip.jpg'
#background = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/background.jpg'
#background2 = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/background2.jpg'

class pygame_car:
    def __init__(self):
        self.name = ''
        self.car_image = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/Pygame/car8.png'
        self.pygame_object = pygame.image.load('C:/Users/ahmed/OneDrive/Desktop/SUMO/Pygame/car8.png')
        self.x_coordinate = 0
        self.y_coordinate = 0
        self.orientation = ''
        self.angle = 0.0
        self.scaled_x = 15
        self.scaled_y = 10
        self.CV_range = 0.0

    def create(self, veh, SUMO_angle, SUMO_pos, Pygame_resolution, Sumo_resolution, CV_range):
        self.name = veh
        margin_x = (Pygame_resolution[0] - Sumo_resolution[0])/2
        margin_y = (Pygame_resolution[1] - Sumo_resolution[1])/2
        self.x_coordinate = SUMO_pos[0] + margin_x - (self.scaled_x/2)
        self.y_coordinate = (Sumo_resolution[1] - SUMO_pos[1]) + margin_y - (self.scaled_y/2)
        if SUMO_angle == 0.0 or SUMO_angle == 360.0:
          self.orientation = 'N'
        elif SUMO_angle == 90.0:
          self.orientation = 'E'
        elif SUMO_angle == 180.0:
          self.orientation = 'S'
        elif SUMO_angle == 270.0:
          self.orientation = 'W'
        elif SUMO_angle > 0.0 and SUMO_angle < 90.0:
          self.orientation = 'NE'
        elif SUMO_angle > 90.0 and SUMO_angle < 180.0:
          self.orientation = 'SE'
        elif SUMO_angle > 180.0 and SUMO_angle < 270.0:
          self.orientation = 'SW'
        elif SUMO_angle > 270.0 and SUMO_angle < 360.0:
          self.orientation = 'NW'

        modified_angle = 360.0 - SUMO_angle + 90.0
        if modified_angle == 360:
            self.angle = 0.0
        else:
            self.angle = modified_angle

        self.CV_range = CV_range

    def draw(self, screen):
        carimg = pygame.transform.scale(self.pygame_object, (self.scaled_x, self.scaled_y))
        carimg_rotated = pygame.transform.rotate(carimg, self.angle)
        screen.blit(carimg_rotated, (self.x_coordinate, self.y_coordinate))
        font = pygame.font.SysFont('Arial', 15)
        pygame.display.set_caption("car game")
        screen.blit(font.render(self.name, True, (0, 0, 0)), (self.x_coordinate, self.y_coordinate + 5.0))
        pygame.draw.circle(screen, (0, 0, 255), (self.x_coordinate, self.y_coordinate), self.CV_range, 1)

    def get_boundries(self):
        return self.pygame_object.get_rect()

    def CV_range_intersects(self, other_vehicle):
        other_vehicle_boundries = other_vehicle.get_boundries()
        center_x = self.x_coordinate
        center_y = self.y_coordinate
        r = self.CV_range
        W = 5.0
        H = 1.5
        #circle_distance_x = abs(center_x - other_vehicle_boundries.centerx)
        #circle_distance_y = abs(center_y - other_vehicle_boundries.centery)
        circle_distance_x = abs(center_x - other_vehicle.x_coordinate)
        circle_distance_y = abs(center_y - other_vehicle.y_coordinate)
        if circle_distance_x > W / 2.0 + r or circle_distance_y > H / 2.0 + r:
            return False
        if circle_distance_x <= W / 2.0 or circle_distance_y <= H / 2.0:
            return True
        corner_x = circle_distance_x - W / 2.0
        corner_y = circle_distance_y - H / 2.0
        corner_distance_sq = corner_x ** 2.0 + corner_y ** 2.0
        return corner_distance_sq <= r ** 2.0

    def copy(self, targeted_vehicle):
        self.name = targeted_vehicle.name
        self.x_coordinate = targeted_vehicle.x_coordinate
        self.y_coordinate = targeted_vehicle.y_coordinate
        self.orientation = targeted_vehicle.orientation
        self.angle = targeted_vehicle.angle
        self.CV_range = targeted_vehicle.CV_range
