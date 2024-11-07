import sys
import subprocess
import os
import shutil


def bytes_to_str(byte_obj):
    try:
        return byte_obj.decode('utf-8')
    except UnicodeDecodeError:
        try:
            return byte_obj.decode('gbk')
        except UnicodeDecodeError:
            return byte_obj


def check_path(p):
    if os.path.exists(p):
        return True
    return False

class Ida2Codeql:
    def __init__(self, codeql_path, dbscheme, extractor):

        assert check_path(codeql_path)
        assert check_path(dbscheme)
        assert check_path(extractor)

        self.codeql_path = codeql_path
        self.extractor = extractor
        self.dbscheme = dbscheme

    def init_dababase(self, src, database_path):
        args = [self.codeql_path, "database", "init", "-l", "go", "-s", src, database_path]

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = p.communicate()
        print(bytes_to_str(stderr))


    def imoprt_trap_file(self, dataset_output, trap_file):
        args = [self.codeql_path, "dataset", "import", "--dbscheme={}".format(self.dbscheme), "--", dataset_output,
                trap_file]

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = p.communicate()
        print(bytes_to_str(stderr))

    def pack_source_file(self, out, src):
        shutil.make_archive(out, 'zip', src)

    def extract_trap_file(self, ast_file, ast_type_file, trap_out_dir):

        print("[*] extract {}".format(ast_file))

        env = {
            "CODEQL_EXTRACTOR_GO_SOURCE_ARCHIVE_DIR": trap_out_dir,
            "CODEQL_EXTRACTOR_GO_TRAP_DIR": trap_out_dir
        }

        args = [self.extractor, "--ast", ast_file, "--type", ast_type_file]
        print(" ".join(args))
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env=env)
        stdout, stderr = p.communicate()
        print(bytes_to_str(stderr))

        npath = ast_file.replace(":", "_")
        trapfile = os.path.join(trap_out_dir, npath + ".trap.gz")
        # print(trapfile, os.path.exists(trapfile))

        if not os.path.exists(trapfile):
            print("generate trap file({}) failed.".format(trapfile))
            exit(1)

        src_path = trap_out_dir
        self.pack_source_file(os.path.join(trap_out_dir, "src"), src_path)
        src_pack_file = os.path.join(trap_out_dir, "src.zip")
        return (trapfile, src_pack_file)

    def extract_trap_file_with_basename(self, base_ast_file_name, trap_out_dir):
        env = {
            "CODEQL_EXTRACTOR_GO_SOURCE_ARCHIVE_DIR": trap_out_dir,
            "CODEQL_EXTRACTOR_GO_TRAP_DIR": trap_out_dir
        }

        args = [self.extractor, "--base-ast-filename", base_ast_file_name]
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env=env)
        stdout, stderr = p.communicate()
        print(bytes_to_str(stderr))

    def collect_ast_modules(self, ast_dir):
        ast_dir = os.path.abspath(ast_dir)
        files = os.listdir(ast_dir)
        modules = []

        type_file_suffix = ".type.json"

        for f in files:
            if not f.endswith(type_file_suffix):
                continue

            base_name = os.path.join(ast_dir, f[:-len(type_file_suffix)])

            ast_files = []
            idx = 0
            while True:
                ast_file = os.path.join(ast_dir, "{}_{}.json".format(base_name, idx))
                if not os.path.exists(ast_file):
                    break

                ast_files.append(ast_file)
                idx += 1

            merged_ast_file = os.path.join(ast_dir, "{}.json".format(base_name))

            if not os.path.exists(merged_ast_file):
                print("collect ast file({}) failed.".format(merged_ast_file))
                exit(1)

            type_file = os.path.join(ast_dir, f)

            m = {
                "type_file": type_file,
                "ast_files": ast_files,
                "base_filename": base_name,
                "merged_ast_file": merged_ast_file,
            }

            modules.append(m)

        return modules

    def generate_database_from_hexray_asts(self, database, ast_dir):
        if os.path.exists(database):
            shutil.rmtree(database)

        os.makedirs(database)

        trap_out_dir = os.path.join(database, "trap/go")
        if not os.path.exists(trap_out_dir):
            os.makedirs(trap_out_dir)

        dataset_out_dir = os.path.join(database, "db-go")

        ast_file = os.path.abspath(sys.argv[5])
        self.init_dababase(os.path.dirname(ast_file), database)

        modules = self.collect_ast_modules(ast_dir)

        for m in modules:
            self.extract_trap_file(m['merged_ast_file'], m['type_file'], trap_out_dir)

        src_path = trap_out_dir
        self.pack_source_file(os.path.join(trap_out_dir, "src"), src_path)
        src_pack_file = os.path.join(trap_out_dir, "src.zip")

        self.imoprt_trap_file(dataset_out_dir, trap_out_dir)
        shutil.move(src_pack_file, os.path.join(database, "src.zip"))


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print('Usage: {} codeql dbscheme extractor database ast_dir'.format(sys.argv[0]))
        exit(1)

    # print(sys.argv)

    ida2codeql = Ida2Codeql(sys.argv[1], sys.argv[2], sys.argv[3])
    database = os.path.abspath(sys.argv[4])
    ast_dir = os.path.abspath(sys.argv[5])
    ida2codeql.generate_database_from_hexray_asts(database, ast_dir)

# python.exe F:\sca\binary2cpg\ida2codeql.py F:\sca\codeql-win64\codeql\codeql.exe F:\sca\codeql-win64\codeql\go\go.dbscheme F:\sca\ida2codeql\awesomeProject\build\go_build_github_com_github_codeql_go_extractor_cli_go_extractor.exe F:\sca\ida2codeql\bprj F:\sca\binary\testbin64\asts
