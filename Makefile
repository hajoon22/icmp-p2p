icmp-p2p: main.o icmp.o checksum.o monocypher.o peer.o protocol.o message.o utils.o stun.o traversal.o
	gcc -o icmp-p2p main.o icmp.o checksum.o monocypher.o peer.o protocol.o message.o utils.o stun.o traversal.o

main.o: main.c
	gcc -c main.c -o main.o
traversal.o: src/traversal/traversal.c src/traversal/traversal.h
	gcc -c src/traversal/traversal.c -o traversal.o
checksum.o: src/traversal/icmp/checksum/checksum.c src/traversal/icmp/checksum/checksum.h
	gcc -c src/traversal/icmp/checksum/checksum.c -o checksum.o
icmp.o: src/traversal/icmp/icmp.c src/traversal/icmp/icmp.h
	gcc -c src/traversal/icmp/icmp.c -o icmp.o
stun.o: src/traversal/stun/stun.c src/traversal/stun/stun.h
	gcc -c src/traversal/stun/stun.c -o stun.o
monocypher.o: src/monocypher/monocypher.c src/monocypher/monocypher.h
	gcc -c src/monocypher/monocypher.c -o monocypher.o
peer.o: src/peer/peer.c src/peer/peer.h
	gcc -c src/peer/peer.c -o peer.o
protocol.o: src/protocol/protocol.c src/protocol/protocol.h
	gcc -c src/protocol/protocol.c -o protocol.o
message.o: src/protocol/message/message.c src/protocol/message/message.h
	gcc -c src/protocol/message/message.c -o message.o
utils.o: src/utils/utils.c src/utils/utils.h
	gcc -c src/utils/utils.c -o utils.o

clean:
	rm -f *.o icmp-p2p
