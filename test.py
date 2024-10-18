""" import msvcrt

print("Press any key...")

while True:
    if msvcrt.kbhit():
        char = msvcrt.getwch()
        print(f"You pressed: {char}")
         """

import sys

sys.stdout.write("<You>")
#sys.stdout.flush()  # This ensures the output appears right away
