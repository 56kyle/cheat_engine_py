
import keyboard
import mouse
import time


if __name__ == '__main__':
    pair = mouse.get_position()
    while True:
        pair = mouse.get_position()
        x, y = pair
        time.sleep(.2)
        mouse.move(x, y)
        print((x, y))


