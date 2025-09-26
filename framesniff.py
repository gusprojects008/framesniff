import sys
import pathlib
import argparser

modules_path = pathlib.Path(__file__).parent / "Core"
sys.path.append(str(modules_path))

from user_operations import Operations

operations = Operations()

def main():
    pass

if __name__ == "__main__":
    main()
