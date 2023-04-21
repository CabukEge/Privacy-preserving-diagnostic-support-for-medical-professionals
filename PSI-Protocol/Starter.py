import subprocess
import sys

# identify the operating System
if sys.platform == 'win32':
    # Windows
    subprocess.run("start cmd /k python idb_node.py", shell=True)
    subprocess.run("start cmd /k python med_node.py", shell=True)
elif sys.platform == 'darwin':
    # macOS
    subprocess.run("open -a Terminal.app python idb_node.py", shell=True)
    subprocess.run("open -a Terminal.app python med_node.py", shell=True)
else:
    # Linux
    subprocess.run("x-terminal-emulator -e python3 idb_node.py", shell=True)
    subprocess.run("x-terminal-emulator -e python3 med_node.py", shell=True)
