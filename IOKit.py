import subprocess
import frida
import sys
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

commandStr = 'sudo lsmp -p $(pidof ' + sys.argv[2] + ') | grep IOKIT-CONNECT | awk \'{print $1, $9}\''
commandVar = Command(commandStr).run()
mappings = list(map(lambda line: [int(line.split(' ')[0], 16), line.split(' ')[1]], commandVar.output.decode().split('\n')[:-1])) # TODO maybe remove last element only if empty LOL but should always be
mappings_str = json.dumps(mappings)

print(f'[ * ] {sys.argv[2]} Mach ports:')
print(commandVar.output.decode())
print(mappings_str)

with open(sys.argv[1], 'r') as f:
    jscode = f.read()

process = frida.attach(sys.argv[2])
script = process.create_script(jscode)
print('[ * ] Action starting shortly... !!!')

script.load()
script.exports.setmappings(mappings_str);

sys.stdin.read()
