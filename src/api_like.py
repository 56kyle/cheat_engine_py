
import os
import subprocess


def main():
    os.system('cd')
    output = os.system(r'..\venv\Scripts\activate && .\frida_2.py "BloonsTD6.exe" "48 8B 43 28 F2 0F11 73"')
    print(output)


if __name__ == '__main__':
    main()
