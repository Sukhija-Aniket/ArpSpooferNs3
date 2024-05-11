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
#include "ns3/icmpv4-l4-protocol.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/bridge-helper.h"
#include <sstream>
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("MITM");

class DetectApp : public Application
{
public:
  DetectApp ();
  virtual ~DetectApp ();
  void Setup (Ptr<Node> node, Ipv4Address addr, Ipv4Address aAddr, Ipv4Address sAddr,
              Ipv4Address vAddr, Address aMac, Address sMac, Address vMac);
  void OnIcmpReceived (Ptr<const Packet> packet, const Ipv4Header &ipv4Header,
                       const Icmpv4Header &icmpHeader);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  void ScheduleTx (void);
  void SendPacket (void);

  Ptr<Node> m_node;
  Ptr<Icmpv4L4Protocol> m_icmpv4L4Protocol;

  Ipv4Address m_addr;
  Ipv4Address m_aAddr;
  Ipv4Address m_sAddr;
  Ipv4Address m_vAddr;

  Address m_aMac;
  Address m_sMac;
  Address m_vMac;

  EventId m_sendEvent;
  bool m_running;
};

DetectApp::DetectApp ()
    : m_node (),
      m_addr (),
      m_aAddr (),
      m_sAddr (),
      m_vAddr (),
      m_aMac (),
      m_sMac (),
      m_vMac (),
      m_sendEvent (),
      m_running (false)
{
}

DetectApp::~DetectApp ()
{
}

void
DetectApp::Setup (Ptr<Node> node, Ipv4Address addr, Ipv4Address aAddr, Ipv4Address sAddr,
                  Ipv4Address vAddr, Address aMac, Address sMac, Address vMac)
{
  m_node = node;
  m_addr = addr;
  m_aAddr = aAddr;
  m_sAddr = sAddr;
  m_vAddr = vAddr;
  m_aMac = aMac;
  m_sMac = sMac;
  m_vMac = vMac;

  Ptr<Icmpv4L4Protocol> icmpv4L4Protocol = m_node->GetObject<Icmpv4L4Protocol> ();
  icmpv4L4Protocol->SetNode (m_node);
  m_icmpv4L4Protocol = icmpv4L4Protocol;
  icmpv4L4Protocol->RegisterExpectedResponse (m_aAddr, Mac48Address::ConvertFrom (m_aMac));
  icmpv4L4Protocol->RegisterExpectedResponse (m_sAddr, Mac48Address::ConvertFrom (m_sMac));
  icmpv4L4Protocol->RegisterExpectedResponse (m_vAddr, Mac48Address::ConvertFrom (m_vMac));
  m_icmpv4L4Protocol->m_icmpReceivedTrace.ConnectWithoutContext (
      MakeCallback (&DetectApp::OnIcmpReceived, this));
  // std::cout << "Setup Completed" << std::endl;
}

class AttackApp : public Application
{
public:
  AttackApp ();
  virtual ~AttackApp ();

  void Setup (Ptr<Node> node, Ptr<NetDevice> dev, Ptr<Ipv4Interface> iface, Ipv4Address addr, Ipv4Address dAddr,
              Ipv4Address saddr, Ipv4Address vAddr, Address dMac, Address sMac, Address vMac);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  void ScheduleTx (void);
  void SendPacket (void);

  Ptr<Node> m_node;
  Ptr<NetDevice> m_device;
  Ptr<Ipv4Interface> m_iface;

  Ipv4Address m_addr;
  Ipv4Address m_dAddr;
  Ipv4Address m_sAddr;
  Ipv4Address m_vAddr;

  Address m_dMac;
  Address m_sMac;
  Address m_vMac;

  EventId m_sendEvent;
  bool m_running;

  ArpL3Protocol m_attacker;
  Ptr<ArpCache> m_arpCache;
};

AttackApp::AttackApp ()
    : m_node (),
      m_device (),
      m_iface (),
      m_addr (),
      m_dAddr(),
      m_sAddr (),
      m_vAddr (),
      m_dMac(),
      m_sMac (),
      m_vMac (),
      m_sendEvent (),
      m_running (false)
{
}

AttackApp::~AttackApp ()
{
}

void
DetectApp::OnIcmpReceived (Ptr<const Packet> packet, const Ipv4Header &ipv4Header,
                           const Icmpv4Header &icmpHeader)
{
  // std::cout << "Running OnIcmpReceived" << std::endl;
  if (icmpHeader.GetType () == Icmpv4Header::ICMPV4_ECHO_REPLY)
    {
      // std::cout << "received echo reply" << std::endl;
    }
  else
    {
      // std::cout << "Some error in cache update" << std::endl;
    }
}

void
AttackApp::Setup (Ptr<Node> node, Ptr<NetDevice> dev, Ptr<Ipv4Interface> iface, Ipv4Address addr,
                  Ipv4Address dAddr, Ipv4Address saddr, Ipv4Address vAddr, Address dMac, Address sMac, Address vMac)
{
  m_node = node;
  m_device = dev;
  m_iface = iface;
  m_addr = addr;
  m_dAddr = dAddr;
  m_sAddr = saddr;
  m_vAddr = vAddr;
  m_dMac = dMac;
  m_sMac = sMac;
  m_vMac = vMac;
  // std::cout << "Setup Completed" << std::endl;
}

void
SendArpPacket (Ptr<const ArpCache> arpCache, Ptr<Packet> packet, Address toMac)
{
  arpCache->GetDevice ()->Send (packet, toMac, ArpL3Protocol::PROT_NUMBER);
}

void
SendIcmpPacket (Ptr<Icmpv4L4Protocol> icmpv4L4Protocol, Ipv4Address myIp, Ipv4Address dAddr)
{
  icmpv4L4Protocol->SendIcmpEchoRequest (myIp, dAddr);
}

// Note update this function to include icmpv4L4Protocol and dAddr in case using one application only.
void
SendCustomArpReply (Ptr<const ArpCache> cache, Ipv4Address myIp, Ipv4Address toIp, Address toMac)
{
  ArpHeader arp;
  arp.SetReply (cache->GetDevice ()->GetAddress (), myIp, toMac, toIp);
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (arp);
  Simulator::Schedule (Seconds (0), &SendArpPacket, cache, packet, toMac);
}

void
DetectApp::StartApplication (void)
{
  m_running = true;
  // std::cout << "Starting Attack application" << std::endl;
  SendPacket ();
}

void
DetectApp::StopApplication (void)
{
  m_running = false;

  if (m_sendEvent.IsRunning ())
    {
      Simulator::Cancel (m_sendEvent);
    }
}

void
AttackApp::StartApplication (void)
{
  // initialize the attacker
  m_attacker.SetNode (m_node);
  m_arpCache = m_attacker.CreateCache (m_device, m_iface);
  m_running = true;
  // std::cout << "Starting Attack application" << std::endl;
  SendPacket ();
  // ScheduleTx();
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

void
DetectApp::SendPacket (void)
{
  // Simulator::Schedule (Seconds (0.1), &SendIcmpPacket, m_icmpv4L4Protocol, m_addr, m_addr);
  // Simulator::Schedule (Seconds (0.1), &SendIcmpPacket, m_icmpv4L4Protocol, m_sAddr, m_addr);
  Simulator::Schedule (Seconds (0.1), &SendIcmpPacket, m_icmpv4L4Protocol, m_vAddr, m_addr);
  ScheduleTx ();
}

void
DetectApp::ScheduleTx ()
{
  if (m_running)
    {
      Time tNext (MilliSeconds (1000));
      m_sendEvent = Simulator::Schedule (tNext, &DetectApp::SendPacket, this);
    }
}

void
AttackApp::SendPacket (void)
{
  // SendCustomArpReply(m_arpCache, m_sAddr, m_vAddr, m_vMac);
  SendCustomArpReply(m_arpCache, m_vAddr, m_sAddr, m_sMac);
  // SendCustomArpReply (m_arpCache, m_addr, m_sAddr, m_sMac);
  // SendCustomArpReply (m_arpCache, m_addr, m_vAddr, m_vMac);
  // std::cout << "stucked here" << std::endl;
  ScheduleTx ();
}

void
AttackApp::ScheduleTx (void)
{
  if (m_running)
    {
      Time tNext (MilliSeconds (1000));
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

void
MacSnifferCallback (std::string context, Ptr<const Packet> packet)
{
  // obtain srcMac and dstMac from packet

  EthernetHeader ethHeader;
  Ipv4Header ipHeader;
  Icmpv4Echo icmpv4Echo;
  Mac48Address srcMac, dstMac;
  Ptr<Packet> copy = packet->Copy ();

  // std::cout<<"obtaining Mac Information"<<std::endl;
  if (copy->PeekHeader(ethHeader)) {
    srcMac = ethHeader.GetSource();
    dstMac = ethHeader.GetDestination();
    copy->RemoveHeader(ethHeader);
  }

  // std::cout<<"obtaining Ip Information"<<std::endl;
  if (copy->PeekHeader (ipHeader) && copy->RemoveHeader (ipHeader) && copy->PeekHeader (icmpv4Echo))
    {
      // Log ICMP details if it's an ICMP packet
      // std::cout<<ipHeader.GetProtocol()<<" okay: "<<Icmpv4L4Protocol::PROT_NUMBER<<std::endl;
      if (ipHeader.GetProtocol () == Icmpv4L4Protocol::PROT_NUMBER)
        {
          NS_LOG_UNCOND("Identifier: " << (uint16_t) icmpv4Echo.GetIdentifier ()<< ", Sequence: " << (uint16_t) icmpv4Echo.GetSequenceNumber ()<<" from: " << srcMac << " to: " << dstMac);
        }
    }
}

int
main ()
{
  //   LogComponentEnable ("UdpClient", LOG_LEVEL_INFO);
  //   LogComponentEnable ("UdpServer", LOG_LEVEL_INFO);
  //   LogComponentEnable ("ArpL3Protocol", LOG_LEVEL_INFO);
  //   LogComponentEnable ("ArpHeader", LOG_LEVEL_INFO);
  LogComponentEnable ("MITM", LOG_LEVEL_ALL);

  uint32_t nPackets = 3;
  uint32_t packetInt = 1000;
  uint32_t propDelay = 200;
  uint32_t delayT = 0;
  uint32_t serverStart = 5; // Server start time in ms
  uint32_t clientStart = 50; // Client start time in ms
  uint32_t stopTime = (clientStart) + (nPackets * packetInt) + (10 * propDelay) +
                      delayT; // Stop the simulation once all packets have been received

  Ptr<OutputStreamWrapper> stdOutput (new OutputStreamWrapper (&std::cout));

  uint32_t nCsma = 4;
  uint32_t victimId = 0;
  uint32_t serverId = 1;
  uint32_t attackerId = 2;
  uint32_t detectorId = 3;

  uint16_t port = 4000;
  uint32_t MaxPacketSize = 32;

  Address victimAddr;
  Address serverAddr;
  Address attackerAddr;
  Address detectorAddr;

  NodeContainer switchNode;
  switchNode.Create (1);

  NodeContainer csmaNodes;
  csmaNodes.Create (nCsma);

  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));

  NetDeviceContainer csmaDevices, switchDevices;
  for (uint32_t i = 0; i < nCsma; i++)
    {
      NetDeviceContainer link =
          csma.Install (NodeContainer (csmaNodes.Get (i), switchNode.Get (0)));
      csmaDevices.Add (link.Get (0));
      switchDevices.Add (link.Get (1));
    }
  BridgeHelper bridge;
  bridge.Install (switchNode.Get (0), switchDevices);

  // define the mac address
  std::stringstream macAddr;
  for (uint32_t i = 0; i < nCsma; i++)
    {
      macAddr << "10:00:00:00:00:0" << i;
      Ptr<NetDevice> nd = csmaDevices.Get (i);
      Ptr<CsmaNetDevice> cd = nd->GetObject<CsmaNetDevice> ();
      cd->SetAddress (ns3::Mac48Address (macAddr.str ().c_str ()));
      // take a copy of victim addr
      if (i == victimId)
        victimAddr = cd->GetAddress ();
      if (i == serverId)
        serverAddr = cd->GetAddress ();
      if (i == attackerId)
        attackerAddr = cd->GetAddress ();
      if (i == detectorId)
        detectorAddr = cd->GetAddress();
      // std::cout << macAddr.str () << std::endl;
      macAddr.str (std::string ());
    }
  // Adding sniffer module
  // std::cout<<"Yes this only: "<<csmaDevices.Get(detectorId)->GetAddress()<<std::endl;
  csmaDevices.Get (detectorId)->TraceConnect ("PromiscSniffer", "SnifferExample", MakeCallback (&MacSnifferCallback));

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
  Ptr<Ipv4Interface> iface = ipv4->GetObject<Ipv4L3Protocol> ()->GetInterface (index);

  //   std::cout<<serverAddr<<" "<<serverId<<" "<<victimId<<" "<<victimAddr<<std::endl;
  //contruct attacker app
  Ptr<AttackApp> attacker = CreateObject<AttackApp> ();
  attacker->Setup (csmaNodes.Get (attackerId), csmaDevices.Get (attackerId), iface,
                   csmaInterfaces.GetAddress (attackerId), csmaInterfaces.GetAddress(detectorId), csmaInterfaces.GetAddress (serverId),
                   csmaInterfaces.GetAddress (victimId), detectorAddr, serverAddr, victimAddr);
  csmaNodes.Get (attackerId)->AddApplication (attacker);
  attacker->SetStartTime (MilliSeconds (clientStart + delayT));
  attacker->SetStopTime (MilliSeconds (stopTime));

  // construct Detector App
  Ptr<DetectApp> detector = CreateObject<DetectApp> ();
  detector->Setup (csmaNodes.Get (detectorId), csmaInterfaces.GetAddress (detectorId),
                   csmaInterfaces.GetAddress (attackerId), csmaInterfaces.GetAddress (serverId),
                   csmaInterfaces.GetAddress (victimId), attackerAddr, serverAddr, victimAddr);
  csmaNodes.Get (detectorId)->AddApplication (detector);
  detector->SetStartTime (MilliSeconds (clientStart + delayT));
  detector->SetStopTime (MilliSeconds (stopTime));

  UdpServerHelper server (port);
  ApplicationContainer apps = server.Install (csmaNodes.Get (serverId));
  Ipv4Address serverIpAddr = csmaInterfaces.GetAddress (serverId);
  apps.Start (MilliSeconds (serverStart + delayT));
  apps.Stop (MilliSeconds (stopTime));

  uint32_t maxPacketCount = nPackets;
  UdpClientHelper client (serverIpAddr, port);
  client.SetAttribute ("MaxPackets", UintegerValue (maxPacketCount));
  client.SetAttribute ("Interval", TimeValue (MilliSeconds (packetInt)));
  client.SetAttribute ("PacketSize", UintegerValue (MaxPacketSize));
  apps = client.Install (csmaNodes.Get (victimId));
  apps.Start (MilliSeconds (clientStart + delayT));
  apps.Stop (MilliSeconds (stopTime));

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  csma.EnablePcapAll ("MITM");
  Simulator::Run ();
  Simulator::Destroy ();
  return 0;
}