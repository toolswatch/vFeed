import os
import glob
import subprocess
import sys

def MigrationContext():
    # Ensure that vFeed has been cloned from GitHub to user's directory
    # Instance: Windows
    # c:\users\<username>\vFeed is the location of cloned reposotiry
    # Instance: Linux
    # /home/<user>/vFeed is the location of the cloned repository
    current_dir = os.getcwd()
    os.chdir(os.path.expanduser("~"))
    return current_dir

# Read Mongo Configuration
def mongoConf():
    with open(os.path.abspath(os.path.expanduser("~"+"/vFeed/migrationScripts/mongo.conf"))) as ConfReader:
        confLine = ''
        for line in ConfReader:
            line = line.strip(' ')
            if 'MongoDBurl' in line:
                confLine = line.split(' ')[1]
        if confLine:
            return
        else:
            print("[-] Error in MongoDBurl, Cannot be empty")
            sys.exit(0)


# Migration to mongo starts headerline
# First Step: Convert to CSV from SQLite table by table
# check the check the `csvexports.sql` for information
## Headers need to be on and mode is csv during export

def do_sqlite_to_csv():
    '''
    Executing sql script in migrationScripts
    '''
    vfeed_db_location = "vFeed/vfeed.db"
    vfeed_migraton_script = "vFeed/migrationScripts/csvexports.sql"
    migration_read = '.read ' + vfeed_migraton_script

    subprocess.check_call([
                        'sqlite3',
                        vfeed_db_location,
                        migration_read
    ])

def do_csv_to_mongo():
    ## From CSV files to mongo database
    mongo_host = mongoConf()
    print(mongo_host)
    csv_path = os.path.expanduser("~"+"/vFeed/csv_exports/")

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

if __name__ == '__main__':
    # Change directory to user's home directory and save previous directory
    current_dir = MigrationContext()
    # Export SQLite to CSV Files
    do_sqlite_to_csv()
    # Export CSV to MongoDB
    do_csv_to_mongo()
    # Change back to previous directory - Undoing previous directory change
    os.chdir(current_dir)
