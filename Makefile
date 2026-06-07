icmp-p2p: main.o icmp.o checksum.o monocypher.o peer.o protocol.o utils.o
	gcc -o icmp-p2p main.o icmp.o checksum.o monocypher.o peer.o protocol.o utils.o

main.o: main.c
	gcc -c main.c -o main.o
icmp.o: src/icmp/icmp.c src/icmp/icmp.h
	gcc -c src/icmp/icmp.c -o icmp.o
checksum.o: src/icmp/checksum/checksum.c src/icmp/checksum/checksum.h
	gcc -c src/icmp/checksum/checksum.c -o checksum.o
monocypher.o: src/monocypher/monocypher.c src/monocypher/monocypher.h
	gcc -c src/monocypher/monocypher.c -o monocypher.o
peer.o: src/peer/peer.c src/peer/peer.h
	gcc -c src/peer/peer.c -o peer.o
protocol.o: src/protocol/protocol.c src/protocol/protocol.h
	gcc -c src/protocol/protocol.c -o protocol.o
utils.o: src/utils/utils.c src/utils/utils.h
	gcc -c src/utils/utils.c -o utils.o

clean:
	rm -f *.o icmp-p2p