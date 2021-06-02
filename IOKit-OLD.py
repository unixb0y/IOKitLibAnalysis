import subprocess
import frida
import sys, os
import json

class Command(object):
    """Run a command and capture it's output string, error string and exit status"""
    def __init__(self, command):
        self.command = command
    def run(self, shell=True):
        import subprocess as sp
        process = sp.Popen(self.command, shell = shell, stdout = sp.PIPE, stderr = sp.PIPE)
        self.pid = process.pid
        self.output, self.error = process.communicate()
        self.failed = process.returncode
        return self
    @property
    def returncode(self):
        return self.failed

kill = False
binary = sys.argv[1]
try:
    use_usb = sys.argv[2] == '-U'
    try:
        ssh_key = sys.argv[3]
    except:
        print('[ERR]: Please specify SSH key when using USB device.')
        kill = True
except:
    use_usb = False

if kill:
    exit()

if use_usb:
    filepath = os.path.expanduser(f'~/.ssh/{ssh_key}')
    if not os.path.isfile(filepath):
        print(f'[ERR]: SSH key {ssh_key} not existing in ~/.ssh/ folder.')
        exit()
    pidStr = f'ssh -i {filepath} root@localhost -p 2222 ps -ef | grep bluetoothd | awk \'{{print $2}}\''
    pidVar = Command(pidStr).run().output.decode()

    commandStr = f'ssh -i {filepath} root@localhost -p 2222 "lsmp -p {pidVar}" | grep IOKIT-CONNECT | awk \'{{print $1, $9}}\''
    commandVar = Command(commandStr).run().output.decode()
    print(commandVar)
    # exit()

else:
    commandStr = f'sudo lsmp -p $(pidof {binary}) | grep IOKIT-CONNECT | awk \'{{print $1, $9}}\''
    commandVar = Command(commandStr).run().output.decode()
    print(commandVar)
    # exit()

mappings = list(map(lambda line: [int(line.split(' ')[0], 16), line.split(' ')[1]], commandVar.split('\n')[:-1])) # TODO maybe remove last element only if empty LOL but should always be
mappings_str = json.dumps(mappings)

print(f'[ * ] { binary } Mach ports:')
print(commandVar)
print(f'{mappings_str}\n')

with open('IOKit-OLD.js', 'r') as f:
    jscode = f.read() %(mappings_str)

if use_usb:
    process = frida.get_usb_device().attach(binary)
else:
    try:
        process = frida.attach(binary)
    except frida.PermissionDeniedError:
        print('[Err]: This binary might need sudo privileges to attach to. Please execute script as sudo.')
        exit()

script = process.create_script(jscode)
print('[ * ] Action starting shortly... !!!')

script.load()

sys.stdin.read()
