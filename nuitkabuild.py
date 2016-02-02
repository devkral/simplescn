#! /usr/bin/env python3
import sys, os
import subprocess
import shutil

if __name__ == "__main__":
    execute = ["/usr/bin/nuitka", "--recurse-not-to=simplescn", "--remove-output", "--output-dir=simplescn_nuitkadist"]
    if "--no-progress" not in sys.argv:
        execute.append("--show-progress")
    if "--backend=clang" in sys.argv:
        execute.append("--clang")
    elif "--backend=mingw" in sys.argv:
        execute.append("--mingw")

    if "--standalone" not in sys.argv:
        pass
        #execute.append("--recurse-none")
    else:
        execute.append("--recurse-all")
        execute.append("--recurse-stdlib")
        execute.append("--standalone")
    
        if "--no-gui" not in sys.argv:
            try:
                import gi
                execute.append("--recurse-to=gi")
            except ImportError:
                pass
        if "--no-markdown" not in sys.argv:
            try:
                import markdown
                execute.append("--recurse-to=markdown")
            except ImportError:
                pass
    
    if os.path.exists("simplescn_nuitkadist"):
        shutil.rmtree("simplescn_nuitkadist")
    
    if os.path.exists("simplescn_nuitkadist.zip"):
        os.remove("simplescn_nuitkadist.zip")
    os.makedirs("simplescn_nuitkadist", exist_ok=True)
    shutil.copytree("simplescn", os.path.join("simplescn_nuitkadist", "simplescn"))
    shutil.copy("simplescn.py", os.path.join("simplescn_nuitkadist", "simplescn.py"))
    execute.append(os.path.join("simplescn_nuitkadist", "simplescn.py"))
    with subprocess.Popen(execute, stdout=sys.stdout, stderr=sys.stderr, universal_newlines=True) as proc:
        proc.wait()
    shutil.make_archive("simplescn_nuitkadist", format="zip", root_dir="./simplescn_nuitkadist")
