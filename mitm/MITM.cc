/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

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

NS_LOG_COMPONENT_DEFINE ("MITM");

class AttackApp : public Application 
{
public:

  AttackApp ();
  virtual ~AttackApp();

  void Setup (Ptr<Node> aNode, Ptr<NetDevice> aDev, Ptr<Ipv4Interface> iface, Ipv4Address aAddr, Ipv4Address saddr, Address sMac, Ipv4Address vAddr, Address vMac);
  void UpdateArpCache(Ipv4Address ip);
  void OnIcmpReceived(Ptr<const Packet> packet, const Ipv4Header &ipv4Header, const Icmpv4Header &icmpHeader);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  void ScheduleTx (void);
  void SendPacket (void);

  Ptr<Node> m_node;
  Ptr<NetDevice> m_device;
  Ptr<Ipv4Interface> m_iface;
  Ptr<Icmpv4L4Protocol> m_icmpv4L4Protocol;

  // Server Info
  Ipv4Address m_aAddr;
  Ipv4Address m_sAddr;
  Address m_sMac;

  // victim info
  Ipv4Address m_vAddr;
  Address m_vMac;

  EventId         m_sendEvent;
  bool            m_running;

  ArpL3Protocol m_attacker;
  Ptr<ArpCache> m_arpCache;
};


AttackApp::AttackApp ()
  :m_node(),
  m_device(),
  m_iface(),
  m_aAddr(),
  m_sAddr(),
  m_sMac(),
  m_vAddr(),
  m_vMac(),
  m_sendEvent (), 
  m_running (false),
  m_icmpv4L4Protocol()
{
}

AttackApp::~AttackApp()
{
}

void AttackApp::OnIcmpReceived(Ptr<const Packet> packet, const Ipv4Header &ipv4Header, const Icmpv4Header &icmpHeader) {
    if (icmpHeader.GetType() == Icmpv4Header::ICMPV4_ECHO_REPLY) {
        AttackApp::UpdateArpCache(ipv4Header.GetSource());
    }
}


 void AttackApp::UpdateArpCache(Ipv4Address ip) {
        // Logic to update or verify ARP cache
        std::cout << "Updating ARP cache for IP: " << ip << std::endl;
        m_attacker.SendArpReply(m_arpCache, m_sAddr, m_vAddr, m_vMac);
        m_attacker.SendArpReply(m_arpCache, m_vAddr, m_sAddr, m_sMac);
        
    }

void
AttackApp::Setup (Ptr<Node> aNode, Ptr<NetDevice> aDev, Ptr<Ipv4Interface> iface, Ipv4Address aAddr, Ipv4Address saddr, Address sMac, Ipv4Address vAddr, Address vMac)
{
  m_node = aNode;
  m_device = aDev;
  m_iface = iface;
  m_aAddr = aAddr;
  m_sAddr = saddr; // Server Address
  m_sMac = sMac;
  m_vAddr = vAddr;
  m_vMac = vMac;
  Ptr<Icmpv4L4Protocol> icmpv4L4Protocol = CreateObject<Icmpv4L4Protocol>();
  m_icmpv4L4Protocol = icmpv4L4Protocol;
  m_icmpv4L4Protocol->m_icmpReceivedTrace.ConnectWithoutContext(MakeCallback(&OnIcmpReceived, this));
}

void
AttackApp::StartApplication (void)
{
  // initialize the attacker
  m_attacker.SetNode(m_node);
  m_arpCache = m_attacker.CreateCache(m_device, m_iface);
  m_running = true;
  m_icmpv4L4Protocol->SendIcmpEchoRequest(m_aAddr, m_sAddr);
  ScheduleTx();
//   SendPacket();
}

void 
AttackApp::StopApplication (void)
{
  m_running = false;

  if (m_sendEvent.IsRunning ())
    {
      Simulator::Cancel (m_sendEvent);
    }
}

// void 
// AttackApp::SendPacket (void)
// {

//   m_attacker.SendArpReply(m_arpCache, m_sAddr, m_vAddr, m_vMac);
//   m_attacker.SendArpReply(m_arpCache, m_vAddr, m_sAddr, m_sMac);
//   std::cout << "stucked here" << std::endl;
//   ScheduleTx ();
// }

void 
AttackApp::SendPacket (void)
{

  m_icmpv4L4Protocol->SendIcmpEchoRequest(m_aAddr, m_sAddr);
  std::cout << "stucked here" << std::endl;
  ScheduleTx ();
}


void 
AttackApp::ScheduleTx(void) {
  if (m_running) {
      Time tNext (MilliSeconds(1000));
      m_sendEvent = Simulator::Schedule (tNext, &AttackApp::SendPacket, this);
    }
}

// void 
// AttackApp::ScheduleTx (void)
// {
//   if (m_running)
//     {
//       Time tNext (MilliSeconds(1000));
//       m_sendEvent = Simulator::Schedule (tNext, &AttackApp::SendPacket, this);
//     }
// }

int 
main ()
{
//   LogComponentEnable ("UdpClient", LOG_LEVEL_INFO);
//   LogComponentEnable ("UdpServer", LOG_LEVEL_INFO);
//   LogComponentEnable ("ArpL3Protocol", LOG_LEVEL_INFO);
//   LogComponentEnable ("ArpHeader", LOG_LEVEL_INFO);
  LogComponentEnable("MITM", LOG_LEVEL_ALL);
  
  uint32_t nPackets = 3;
  uint32_t packetInt = 1000;
  uint32_t propDelay = 200;
  uint32_t delayT = 0;
  uint32_t serverStart = 5;          // Server start time in ms
  uint32_t clientStart = 50;          // Client start time in ms
  uint32_t stopTime = (clientStart) + (nPackets*packetInt) + (10*propDelay) + delayT; // Stop the simulation once all packets have been received

  Ptr<OutputStreamWrapper> stdOutput(new OutputStreamWrapper(&std::cout));
  
  uint32_t nCsma = 3;
  uint32_t attackerId = 2;
  uint32_t serverId = 1;  
  uint32_t victimId = 0;

  uint16_t port = 4000;
  uint32_t MaxPacketSize = 32;
  
  Address victimAddr;
  Address serverAddr;

  NodeContainer csmaNodes;
  csmaNodes.Create (nCsma);
  
  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));

  NetDeviceContainer csmaDevices = csma.Install (csmaNodes);

  // define the mac address
  std::stringstream macAddr;
  for( uint32_t i = 0; i < nCsma; i++ )  
  {
    macAddr << "00:00:00:00:00:0" << i;
    Ptr<NetDevice> nd = csmaDevices.Get (i);
    Ptr<CsmaNetDevice> cd = nd->GetObject<CsmaNetDevice> ();
    cd->SetAddress(ns3::Mac48Address(macAddr.str().c_str()));
    // take a copy of victim addr
    if(i == victimId) victimAddr = cd->GetAddress();
    if (i == serverId) serverAddr = cd->GetAddress();
    std::cout << macAddr.str()<<std::endl;
    macAddr.str(std::string());
  }

  InternetStackHelper stack;
  stack.Install (csmaNodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer csmaInterfaces;
  csmaInterfaces = address.Assign (csmaDevices);
  
  // get IPV4 interface for the attacker
  std::pair<Ptr<Ipv4>, uint32_t> returnValue = csmaInterfaces.Get (attackerId);
  Ptr<Ipv4> ipv4 = returnValue.first;
  uint32_t index = returnValue.second;
  Ptr<Ipv4Interface> iface =  ipv4->GetObject<Ipv4L3Protocol> ()->GetInterface (index);

//   std::cout<<serverAddr<<" "<<serverId<<" "<<victimId<<" "<<victimAddr<<std::endl;
  //contruct attacker app
  Ptr<AttackApp> attacker = CreateObject<AttackApp> ();
  attacker->Setup(csmaNodes.Get(attackerId), csmaDevices.Get(attackerId), iface,  csmaInterfaces.GetAddress(attackerId), csmaInterfaces.GetAddress(serverId), serverAddr, csmaInterfaces.GetAddress(victimId), victimAddr);
  csmaNodes.Get (attackerId)->AddApplication (attacker);
  attacker->SetStartTime (MilliSeconds (clientStart + delayT ));
  attacker->SetStopTime (MilliSeconds (stopTime));
  
  UdpServerHelper server (port);
  ApplicationContainer apps = server.Install (csmaNodes.Get (1));
  Ipv4Address sourceAddr = csmaInterfaces.GetAddress(+1); 	
  apps.Start (MilliSeconds (serverStart + delayT));
  apps.Stop (MilliSeconds (stopTime));

  uint32_t maxPacketCount = nPackets;
  UdpClientHelper client (sourceAddr, port);
  client.SetAttribute ("MaxPackets", UintegerValue (maxPacketCount));
  client.SetAttribute ("Interval", TimeValue (MilliSeconds (packetInt)));
  client.SetAttribute ("PacketSize", UintegerValue (MaxPacketSize));
  apps = client.Install (csmaNodes.Get (0));
  apps.Start (MilliSeconds (clientStart + delayT));
  apps.Stop (MilliSeconds (stopTime));
 
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
 
  csma.EnablePcapAll("MITM"); 
  Simulator::Run ();
  Simulator::Destroy ();
  return 0;
}