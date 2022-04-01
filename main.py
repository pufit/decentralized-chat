import argparse
import asyncio
import logging
import threading

from fastchat.protocol.main import Protocol, Storage, const


def build_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-H', '--host', type=str,
        help='Host to serve',
        default='127.0.0.1'
    )

    parser.add_argument(
        '-p', '--port', type=int,
        help='Port to serve',
        default=9001
    )

    parser.add_argument(
        '-l', '--logging-level', type=str,
        help='Logging level',
        default='DEBUG',
    )

    parser.add_argument(
        '-t', '--target', type=str,
        help='Host to connect',
        default='127.0.0.1:9001'
    )

    parser.add_argument(
        '-n', '--nickname', type=str,
        help='nickname',
    )

    return parser


def cli(protocol):
    while True:
        message = input()

        if message.startswith('/'):
            if message == '/list':
                print(Storage.nets)
            else:
                print('>>> Unknown command!')
        else:
            protocol.send_message(0, message)


async def main():
    args = build_parser().parse_args()

    if not args.nickname:
        print('nickname? ')
        nickname = input('> ')
        Storage.nickname = nickname
    else:
        Storage.nickname = args.nickname

    logging.basicConfig(
        level=logging.getLevelName(args.logging_level),
        format='%(name)-24s [LINE:%(lineno)-3s]# %(levelname)-8s [%(asctime)s]  %(message)s'
    )

    logging.info('%s:%s STARTING!', args.host, args.port)

    protocol: Protocol
    _, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: Protocol(args.host, args.port),
        local_addr=(args.host, args.port)
    )

    if args.target:
        protocol.send(0, args.target, b'', const.Flags.SYNC_REQUEST)

    threading.Thread(target=cli, args=(protocol,), daemon=True).start()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.create_task(main())
    loop.run_forever()
