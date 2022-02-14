import binascii
from pyasn1.codec.der import encoder as DERencoder
from pyasn1.compat.octets import octs2ints, int2oct
from BSM import BSMdata
import traci
from j2735 import *
import datetime


BSMcounter = 0

def createJ2735BSM_XY(id_name, X, Y, speed, acceleration, angle):
	# - Fixed TemporaryID
	# - Fixed Accuracy
	# - Fixed Heading

	BSM = BasicSafetyMessage()
	BSM.setComponentByName('msgID', 2) #basicSafetyMessage
	
	global BSMcounter
	BSM.setComponentByName('msgCnt', BSMcounter)
	BSM.setComponentByName('id', id_name)
	nowTime = datetime.datetime.now()
	timeMS = int(str(nowTime.microsecond)[0:4])
	newX = int(X * 100)
	newY = int(Y * 100)
	BSM.setComponentByName('secMark', timeMS)
	BSM.setComponentByName('lat', newX)
	BSM.setComponentByName('long', newY)
	newSpeed = int(speed*100)
	newAccel = int(acceleration*100)
	transAndSpeed = TransmissionAndSpeed()
	transAndSpeed.setComponentByName('state', 7)
	transAndSpeed.setComponentByName('speed',newSpeed)
	BSM.setComponentByName('speed',transAndSpeed)
	BSM.setComponentByName('angle', str(int(angle)))
	BSM.setComponentByName('accelSet', str(newAccel))
	#BSM.setComponentByName('brakes', "nn")
	vehicleSize = VehicleSize()
	vehicleWidth = 2
	vehicleLength = 5
	vehicleSize.setComponentByName('width', vehicleWidth)
	vehicleSize.setComponentByName('length', vehicleLength)
	BSM.setComponentByName('size', vehicleSize)

	# Increase BSM sequencenumber and Prevent overflow
	BSMcounter = BSMcounter+1 
	if(BSMcounter==127):
		BSMcounter = 0
	
	return BSM

def decodeJ2735BSM_XY(BSM, traci_status):
	app_bsm = BSMdata()
	veh_name = 'veh.' + str(BSM.getComponentByName('id'))
	app_bsm.set_sender(veh_name)
	app_bsm.set_senderType('passenger')
	app_bsm.set_recipient('broadcast')
	if traci_status:
		app_bsm.set_lane(traci.vehicle.getLaneID(veh_name))
		app_bsm.set_maxSpeed(traci.vehicle.getMaxSpeed(veh_name))
		app_bsm.set_lane_pos(traci.vehicle.getLanePosition(veh_name))
	else:
		app_bsm.set_lane('')
		app_bsm.set_maxSpeed(0.0)
		app_bsm.set_lane_pos(0.0)
	angle = float(BSM.getComponentByName('angle'))
	transAndSpeed = BSM.getComponentByName('speed')
	speed = float(transAndSpeed[1])/100.0
	accel = float(BSM.getComponentByName('accelSet'))/100.0
	pos_x = float(BSM.getComponentByName('lat'))/100.0
	pos_y = float(BSM.getComponentByName('long'))/100.0
	pos_z = 0.0
	pos = [pos_x, pos_y, pos_z]
	app_bsm.set_speed(speed)
	app_bsm.set_accel(accel)
	app_bsm.set_angle(angle)
	app_bsm.set_brakes(0.0)
	app_bsm.set_pos(pos)
	return app_bsm

def createJ2735BSM(status, latitude,longitude, altitude, speed, vehicleWidth, vehicleLength):
	# - Fixed TemporaryID
	# - Fixed Accuracy
	# - speed in m/s
	# - Fixed Heading
	# - Fixed Angle
	# - Fixed Acceleration

	BSM = BasicSafetyMessage()
	BSM.setComponentByName('msgID',2) #basicSafetyMessage

	global BSMcounter
	BSM.setComponentByName('msgCnt',BSMcounter)
	BSM.setComponentByName('id',status)

	nowTime = datetime.datetime.now()
	timeMS = int(str(nowTime.microsecond)[0:4])

	#FAZER SPLIT PELO PONTO E FAZER O ENCODE
	newlat = str(latitude).replace(".","")
	newlon = str(longitude).replace(".","")


	BSM.setComponentByName('secMark',timeMS)
	BSM.setComponentByName('lat',newlat)
	BSM.setComponentByName('long',newlon)
	BSM.setComponentByName('elev',altitude)
	BSM.setComponentByName('accuracy',"0000")

	newSpeed = int(float(speed)*100)
	#newSpeedHex = hex(newSpeed)
	#newSpeedHex = newSpeedHex.split("x")

	transAndSpeed = TransmissionAndSpeed()
	transAndSpeed.setComponentByName('state',7)
	transAndSpeed.setComponentByName('speed',newSpeed)

	BSM.setComponentByName('speed',transAndSpeed)
	BSM.setComponentByName('heading',0)
	BSM.setComponentByName('angle',"0")
	BSM.setComponentByName('accelSet',"acceler")
	BSM.setComponentByName('brakes',"nn")

	vehicleSize = VehicleSize()
	vehicleSize.setComponentByName('width',vehicleWidth)
	vehicleSize.setComponentByName('length',vehicleLength)

	BSM.setComponentByName('size',vehicleSize)

	#print(BSM.prettyPrint())

	# Increase BSM sequencenumber and Prevent overflow
	BSMcounter = BSMcounter+1
	if(BSMcounter==127):
		BSMcounter = 0

	encodedMessage = DERencoder.encode(BSM)
	return encodedMessage

def createALaCarte(appID,initTS, recvTS, sourceIP, destinationIP, destPort ,content):
	ALC = ALaCarte()	
	ALC.setComponentByName('msgID', 1)
	ALC.setComponentByName('appID',appID)
	ALC.setComponentByName('initTS',initTS)
	ALC.setComponentByName('recvTS',recvTS)
	ALC.setComponentByName('source',sourceIP)
	ALC.setComponentByName('destination',destinationIP)
	ALC.setComponentByName('destPort',destPort)
	ALC.setComponentByName('appData', content)
	encodedMessage = DERencoder.encode(ALC)
	
	return encodedMessage

def hexdump_with_index(octets):
	return ' '.join(
		['%s%.2X' % (n % 16 == 0 and ('\n%.5d: ' % n) or '', x)
		 for n, x in zip(range(len(octets)), octs2ints(octets))]
	)

def hexdump(octets):
	return ' '.join(
		['%.2X' % x
		 for x in octs2ints(octets)]
	)

def hexdump2(octets):
	return ' '.join(
		["{:02x}".format(ord(c))
		 for c in octets]
	)


def hexDecode(hex):
	message = ''
	octs = hex.split(' ')
	for c in octs:
		if c != '' or '\n':
			line_int = int(c, 16)
			char = str(int2oct(line_int), 'utf-8')
			if line_int == 64:
				break
			message += char
	return message

def insert_spaces(text):
	return " ".join(text[i:i+2] for i in range(0, len(text), 2))

def remove_spaces(text):
	return text.replace(" ", "")

def asn1Decode(message):
	start_index = 0
	lines = message.split(' ')
	#print(lines)
	count_line = (lines[2].split('=')[1]).split('\n')[0]
	#print('count_line:',count_line)
	id_line = (lines[3].split('=')[1]).split('\n')[0]
	#print('id_line:',id_line)
	if len(id_line) == 1:
		start_index = 7
	elif len(id_line) == 2:
		start_index = 6
	elif len(id_line) == 3:
		start_index = 5
	elif len(id_line) == 4:
		start_index = 4
	secMark_line = (lines[start_index].split('=')[1]).split('\n')[0]
	#print('secMark_line:', secMark_line)
	lat_line = (lines[start_index + 1].split('=')[1]).split('\n')[0]
	#print('lat_line:', lat_line)
	lon_line = (lines[start_index + 2].split('=')[1]).split('\n')[0]
	#print('lon_line:', lon_line)
	speed_line = (lines[start_index + 7].split('=')[1]).split('\n')[0]
	#print('speed_line:', speed_line)
	angle_line = (lines[start_index + 8].split('=')[1]).split('\n')[0]
	#print('angle_line:', angle_line)
	accel_line = (lines[start_index + 9].split('=')[1]).split('\n')[0]
	#print('accel_line:', accel_line)
	w_line = (lines[start_index + 12].split('=')[1]).split('\n')[0]
	#print('w_line:', w_line)
	l_line = (lines[start_index + 14].split('=')[1]).split('\n')[0]
	#print('l_line:', l_line)
	bsmasn1 = BasicSafetyMessage()
	bsmasn1.setComponentByName('msgID',2) #basicSafetyMessage
	bsmasn1.setComponentByName('msgCnt',count_line)
	bsmasn1.setComponentByName('id',id_line.ljust(4))
	bsmasn1.setComponentByName('secMark',secMark_line)
	bsmasn1.setComponentByName('lat',lat_line)
	bsmasn1.setComponentByName('long',lon_line)
	bsmasn1.setComponentByName('accuracy',"0000")
	transAndSpeed = TransmissionAndSpeed()
	transAndSpeed.setComponentByName('state',7)
	transAndSpeed.setComponentByName('speed',speed_line)
	bsmasn1.setComponentByName('speed',transAndSpeed)
	bsmasn1.setComponentByName('heading',0)
	bsmasn1.setComponentByName('angle',angle_line)
	bsmasn1.setComponentByName('accelSet',accel_line)
	bsmasn1.setComponentByName('brakes',"nn")
	vehicleSize = VehicleSize()
	vehicleSize.setComponentByName('width',w_line)
	vehicleSize.setComponentByName('length',l_line)
	bsmasn1.setComponentByName('size',vehicleSize)
	return bsmasn1

def format_name(pad, veh_name):
	veh_field = ""
	num = veh_name[pad:]
	for element in range(0, 4):
		if element < len(num):
			veh_field += num[element]
		else:
			veh_field += " "
	return veh_field

