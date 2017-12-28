import sys
from quake import Quake

def main():
    def get_connection_info():
        change_create = True
        change_host = True
        host = -1

        while True:
            if change_host:
                host = input("Host/IP-address (print [exit] to change quit): ")
                if host == 'exit':
                    continue
                elif len(host) == 0:
                    print 'Try again'
                    continue
                elif host == 'exit':
                    print 'Bye-bye\n', False
                    sys.exit()
                else:
                    continue
            change_host = True

            port = input("Port (print [back] to change host): ")

            if port == 'back':
                continue
            elif len(port) == 0:
                print 'Try again'
                change_host = False
                continue
            elif not port.isdigit() or int(port) < 1 or int(port) > 65535:
                print 'Wrong value'
                change_host = False
                continue

            return host, int(port)

    while True:
        host, port = get_connection_info()

        quake = Quake(host, port)
        break


if __name__ == '__main__':
    main()
