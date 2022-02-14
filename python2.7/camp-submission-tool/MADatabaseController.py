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
import happybase

def connect_to_ma_database():
    connection = happybase.Connection(host='192.168.201.162', port=9090)
    connection.open()
    return connection

def query_ma_database(table):
    connection = connect_to_ma_database()
    mbr_table = connection.table(table)
    count = 0
    for row in mbr_table.scan(include_timestamp=True):
        count += 1
    print count
    connection.close()

def clear_ma_mbr_database_table():
    connection = connect_to_ma_database()
    mbr_table = connection.table('MisbehaviorReports')
    for row in mbr_table.scan():
        mbr_table.delete(row[0])
    print "MA misbehavior report table has been cleared"

