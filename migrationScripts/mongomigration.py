import os
import glob
import subprocess

# Ensure that vFeed has been cloned from GitHub to user's directory
# Instance: Windows
# c:\users\<username>\vFeed is the location of cloned reposotiry
# Instance: Linux
# /home/<user>/vFeed is the location of the cloned repository

'''
This is a windows only path - needs to be changed for linux
'''
os.chdir(os.path.expanduser("~"))
csv_path = os.path.expanduser("~"+"/vFeed/csv_exports/")
vfeed_db_location = "vFeed/vfeed.db"
vfeed_migraton_script = "vFeed/migrationScripts/csvexports.sql"
migration_read = '.read ' + vfeed_migraton_script

# Migration to mongo starts headerline
# First Step: Convert to CSV from SQLite table by table
# check the check the `csvexports.sql` for information
## Headers need to be on and mode is csv during export

'''
Executing sql script
'''
subprocess.check_call([
                        'sqlite3',
                        vfeed_db_location,
                        migration_read
])

## From CSV files to mongo database
csv_path = os.path.expanduser("~"+"/vFeed/csv_exports/")
# Change the host
mongo_host = 'localhost:27017'
for csv_file in glob.glob(csv_path+'*.csv'):
    table_name = csv_file.split('\\') if '\\' in csv_file else csv_file.split('/')
    table_name = table_name[len(table_name)-1].replace('.csv', '')
    subprocess.check_call([
                            'mongoimport',
                            '--host',
                            mongo_host,
                            '-d',
                            'vfeed',
                            '-c',
                            table_name,
                            '--type',
                            'csv',
                            '--file',
                            csv_file,
                            '--headerline'
                        ])

    print("[+] Imported collection: {} --> vfeed MongoDB".format(table_name))
