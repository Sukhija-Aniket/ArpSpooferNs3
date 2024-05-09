#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include <sstream>   
#include <iostream> 


using namespace ns3;

struct ICMPHeader {
    uint8_t type;
    uint8_t code;  // 0 for both Echo Request and Echo Reply
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequenceNumber;    
    Address macAddress;
    Ipv4Address ipv4Address;
};

