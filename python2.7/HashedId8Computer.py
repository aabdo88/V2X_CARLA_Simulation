#  (C) Copyright 2017, 2018 Crash Avoidance Metrics Partners LLC, VSC5 Consortium
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# 
from __future__ import print_function
from optparse import OptionParser
from pkencrypt import *

parser=OptionParser()
parser.add_option("-d", "--data", dest="data", help="data", metavar="DATA")
(options,args)=parser.parse_args()

full_id_8 = sha256(options.data.decode('hex')).hexdigest()
hashedId8 = full_id_8[-16:]
print(hashedId8)


