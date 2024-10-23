import subprocess
import os
import threading
import sys

try:
    import queue
except ImportError:
    import Queue as queue


class AnalyseThread(threading.Thread):

    def __init__(self, ida_path, script_path, input_qeueue):
        threading.Thread.__init__(self)
        self.input_qeueue = input_qeueue
        self.ida_path = ida_path
        self.script_path = os.path.abspath(script_path)
        if not os.path.exists(self.script_path):
            raise Exception("{} don't exit!".format(self.script_path))

    def ida_analyse(self, ida_path, script_path, input_path):
        # print input_path
        command = '"{}" -A -c -S"{} from_dumper" {}'.format(ida_path, script_path, input_path)
        print(command)
        p = subprocess.Popen(command, shell=True, cwd=os.getcwd())
        p.wait()

        if p.stdout:
            print(p.stdout.read())

        if p.stderr:
            print(p.stderr.read())

    def run(self):
        while True:
            try:
                input_path = self.input_qeueue.get_nowait()
                self.ida_analyse(self.ida_path, self.script_path, input_path)
            except queue.Empty:
                break
            except Exception as e:
                print(e)
                break


class IDADumper:

    def __init__(self, ida, ida_sc="dump_ast.py"):
        self.ida = ida

        cur_dir = os.path.dirname(__file__)
        ida_sc = os.path.join(cur_dir, ida_sc)
        self.ida_sc = os.path.abspath(ida_sc)

        if not os.path.exists(self.ida_sc):
            raise Exception("{} don't exist.".format(self.ida_sc))

    def is_bad_file(self, fname):
        suffix = [".nam", ".til", ".id0", ".id1", ".id2", ".idb", ".i64", ".json", ".txt", ".c", ".h"]

        if not os.path.isfile(fname):
            return True

        for s in suffix:
            if fname.endswith(s):
                return True

        return False

    def do_dump(self, input_dir, thread_count=4):

        ida_sc = self.ida_sc
        q = queue.Queue()

        files = []

        for i in os.listdir(input_dir):
            file_path = os.path.join(input_dir, i)

            if self.is_bad_file(file_path):
                continue
            q.put(file_path)
            files.append(file_path)

        ths = []
        for i in range(thread_count):
            th = AnalyseThread(self.ida, ida_sc, q)
            th.start()
            ths.append(th)

        for i in ths:
            i.join()

        return files


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: {} ida_path <input_dir>".format(sys.argv[0]))
        sys.exit(1)

    ida_path = sys.argv[1]
    input_dir = sys.argv[2]

    dumper = IDADumper(ida_path)
    files = dumper.do_dump(input_dir)
