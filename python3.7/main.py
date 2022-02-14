from __future__ import print_function
# ==============================================================================
# -- imports -------------------------------------------------------------------
# ==============================================================================
import os
import sys
import pygame
import traci
from CV import Connect_Vehicle
from Draw_car import pygame_car
from Draw_rsu import pygame_rsu
from infrastructure import communications_service
import time

gray = (119, 118, 110)
black = (0, 0, 0)
red = (255, 0, 0)
white = (255, 255, 255)
green = (0, 200, 0)
blue = (0, 0, 200)
bright_red = (255, 0, 0)
bright_green = (0, 255, 0)
bright_blue = (0, 0, 255)

pygame.init()

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print('Hello')
    if 'SUMO_HOME' in os.environ:
        tools = os.path.join(os.environ['SUMO_HOME'], 'tools')
        sys.path.append(tools)
        print('SUMO_HOME is in os.environ')
    else:
        sys.exit("please declare environment variable 'SUMO_HOME'")

    print('Start SUMO')
    sumoBinary = "C:/Program Files (x86)/Eclipse/Sumo/bin/sumo-gui"
    #folder_name = "C:/Users/ahmed/OneDrive/Desktop/SUMO/examples/"
    #file_name = "Town04.sumocfg"

    folder_name = "C:/Users/ahmed/OneDrive/Desktop/SUMO/sumo_example_3/"
    file_name = "StudyArea.sumocfg"

    sumoCmd = [sumoBinary, "-c", folder_name + file_name]

    # Set up the drawing window
    os.environ['SDL_VIDEO_WINDOW_POS'] = "%d,%d" % (250, 250)
    #Pygame_resolution = [1950, 850]
    #Sumo_resolution = [1950, 850]
    Pygame_resolution = [500, 500]
    Sumo_resolution = [100, 100]

    DSRC_range = 50
    #DSRC_range = 150
    rsu_range = 40

    screen = pygame.display.set_mode(Pygame_resolution)
    screen.fill(white)

    pygame.display.update()
    CS = communications_service()

    traci.start(sumoCmd)
    print('Start Simulation')

    #draw_rsu = pygame_rsu()
    #draw_rsu.create('rsu_1', 100.0, 100.0, rsu_range)
    #draw_rsu.create('rsu_2', 300.0, 100.0, rsu_range)

    step = 0
    while step < 300:
        traci.simulationStep()
        start = time.time()
        print('step', step)
        vehicle_id_list = traci.vehicle.getIDList()
        # vclass_list = traci.vehicle.getVehicleClass(vehicle_id_list)
        # print([veh for veh in vehicle_id_list])
        # print([traci.vehicle.getPosition(veh) for veh in vehicle_id_list])
        # print([traci.vehicle.getLanePosition(veh) for veh in vehicle_id_list])
        step += 1

        # pygame.event.pump()
        for event in pygame.event.get():
            # if event object type is QUIT
            if event.type == pygame.QUIT:
                pygame.quit()

        screen.fill(white)

        #draw_rsu.draw(screen)

        cvs = []
        # Draw a car
        for veh in vehicle_id_list:
            angle = traci.vehicle.getAngle(veh)
            pos = traci.vehicle.getPosition(veh)
            draw_vehicle = pygame_car()
            draw_vehicle.create(veh, angle, pos, Pygame_resolution, Sumo_resolution, DSRC_range)
            draw_vehicle.draw(screen)

            cv = Connect_Vehicle()
            Encrypt_status = True
            cv.read_and_send_parameters(veh, draw_vehicle, 8, Encrypt_status)
            #cv.read_and_send_parameters(veh, draw_vehicle, 0, Encrypt_status)
            cvs.append(cv)
        pygame.display.update()
        pygame.time.delay(10)
        # print(cv_list)

        if Encrypt_status:
            #rsus = draw_rsu.get_RSUs()
            CS.V2V(cvs)
            #CS.V2I(rsus, cvs)
        print('simulation time step:', traci.simulation.getTime())
        print('time taken is:', time.time() - start)
        print('\n')
        # Flip the display
        # pygame.display.flip()

    traci.close()
    # Done! Time to quit.
    pygame.quit()

