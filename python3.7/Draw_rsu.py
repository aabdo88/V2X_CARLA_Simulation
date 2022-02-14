import pygame

#grass = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/grass.jpg'
#yellow_strip = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/yellow_strip.jpg'
#strip = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/strip.jpg'
#background = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/background.jpg'
#background2 = 'C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/Pygame/background2.jpg'

class pygame_rsu:
    def __init__(self):
        self.name = 'RSUs'
        self.pygame_object = pygame.image.load('C:/Users/ahmed/OneDrive/Desktop/SUMO/Pygame/rsu.png')
        self.rsu_list = []
        self.scaled_x = 15
        self.scaled_y = 30

    def create(self, name, pos_x, pos_y, rsu_range):
        rsu = {
            "name": name,
            "x": pos_x,
            "y": pos_y,
            "range": rsu_range
        }
        self.rsu_list.append(rsu)

    def draw(self, screen):
        rsuimg = pygame.transform.scale(self.pygame_object, (self.scaled_x, self.scaled_y))
        for rsu in self.rsu_list:
            name = rsu['name']
            x_coordinate = float(rsu['x'])
            y_coordinate = float(rsu['y'])
            range = float(rsu['range'])
            screen.blit(rsuimg, (x_coordinate, y_coordinate))
            font = pygame.font.SysFont('Arial', 15)
            screen.blit(font.render(name, True, (0, 0, 0)), (x_coordinate, y_coordinate + 15.0))
            pygame.draw.circle(screen, (0, 0, 255), (x_coordinate, y_coordinate), range, 1)

    def RSU_range_intersects(self, rsu, vehicle):
        center_x = float(rsu['x'])
        center_y = float(rsu['y'])
        r = float(rsu['range'])
        W = 5.0
        H = 1.5
        circle_distance_x = abs(center_x - vehicle.x_coordinate)
        circle_distance_y = abs(center_y - vehicle.y_coordinate)
        if circle_distance_x > W / 2.0 + r or circle_distance_y > H / 2.0 + r:
            return False
        if circle_distance_x <= W / 2.0 or circle_distance_y <= H / 2.0:
            return True
        corner_x = circle_distance_x - W / 2.0
        corner_y = circle_distance_y - H / 2.0
        corner_distance_sq = corner_x ** 2.0 + corner_y ** 2.0
        return corner_distance_sq <= r ** 2.0

    def get_RSUs(self):
        return self.rsu_list



