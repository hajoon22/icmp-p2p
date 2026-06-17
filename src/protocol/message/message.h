#ifndef MESSAGE_H
#define MESSAGE_H

#include "../../icmp/icmp.h"

void parse_message(int s, struct icmp_unreach *rp);

#endif
