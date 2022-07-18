from pathlib import Path
import os
from time import sleep
import subprocess


def edit_file_in_vim(old_content, mode):
    Path("/tmp/seqFS").write_text(old_content)
    pid = os.fork()
    if pid == 0:
        if mode == "r":
            os.execvp("vim", ["vim", "-R", "/tmp/seqFS"])
        else: # rw, owner
            os.execvp("vim", ["vim", "/tmp/seqFS"])
        print("unreachable")
    os.wait()
    return Path("/tmp/seqFS").read_text()
