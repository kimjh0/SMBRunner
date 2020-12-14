import os
import subprocess
import win32evtlog
import sys
import admin

if not admin.isUserAdmin():
    admin.runAsAdmin()
    exit(0)


def read_log():
    server = 'localhost'  # name of the target computer to get event logs
    logtype = 'System'  # 'Application' # 'Security'
    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                print('Event Category:', event.EventCategory)
                print('Time Generated:', event.TimeGenerated)
                print('Source Name:', event.SourceName)
                print('Event ID:', event.EventID)
                print('Event Type:', event.EventType)
                data = event.StringInserts
                if data:
                    print('Event Data:')
                    for msg in data:
                        print(msg)
                print()


def run_powershell(cmd):
    p = subprocess.Popen(['powershell.exe', cmd],
                         stdout=subprocess.PIPE)

    v = p.communicate()
    ret = v[0].decode('euc-kr')
    print(ret)

    if v[1] is not None:
        raise Exception('powershell return error')

    return ret


def detect_feature_smb1():
    ret = run_powershell('Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol')

    for i in ret.split('\r\n'):
        if i.find('State') != 0:
            continue
        if i.find('Enabled') > 0:
            return True
        else:
            return False


def enable_feature_smb1():
    run_powershell('Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName SMB1Protocol')


def disable_feature_smb1():
    run_powershell('Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName SMB1Protocol')


def detect_configuration_smb1():
    ret = run_powershell('Get-SmbServerConfiguration')

    for i in ret.split('\r\n'):
        if i.find('EnableSMB1Protocol') != 0:
            continue
        if i.find('True') > 0:
            return True
        else:
            return False


def enable_configuration_smb1():
    run_powershell('Set-SmbServerConfiguration -Force -EnableSMB1Protocol $true')
    run_powershell('Set-SmbServerConfiguration -Force -EnableAuthenticateUserSharing $false')
    run_powershell('Set-SmbServerConfiguration -Force -EnableSecuritySignature $false')


def disable_configuration_smb1():
    run_powershell('Set-SmbServerConfiguration -Force -EnableSMB1Protocol $false')


def find_smb_share(path, name):
    ret = run_powershell('Get-Smbshare')

    for i in ret.split('\r\n')[3:]:
        if i.find(name) == 0:
            return True
        if i.find(path + ' ') == 0:
            return True

    return False


def make_smb_share(path, name):
    if find_smb_share(path, name) is True:
        return

    cmd = ('New-SmbShare -Name %s -Path %s | Grant-SmbShareAccess -AccountName Guest -AccessRight Full -Force'
           % (name, path))
    run_powershell(cmd)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        exit(-1)

    if detect_feature_smb1() is False:
        print('Enable feature SMB1')
        enable_feature_smb1()

    if detect_configuration_smb1() is False:
        print('Enable configuration SMB1')
        enable_configuration_smb1()

    make_smb_share(sys.argv[1], sys.argv[2])

    os.system('pause')
