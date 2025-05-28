from core import PacketSniffer
from ArgParse import parse_args

def main():
    args = parse_args()

    sniffer = PacketSniffer(interface=args.interface,
        count=args.count if args.count else None,
        timeout = args.timeout,
        whichFilter=args.filter)

    sniffer.sniff_packets()
    sniffer.print_packets()


if __name__ == "__main__":
    print("ScapyTapper")
    main()
