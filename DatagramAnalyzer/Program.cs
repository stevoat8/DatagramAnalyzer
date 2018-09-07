using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace DatagramAnalyzer
{
    class Program
    {
        static void Main(string[] args)
        {
            //InterpretPacketSample();


            PacketDevice device = SelectDevice();

            // Open the selected device
            using (PacketCommunicator communicator = device.Open(
                    65536,                                  // portion of the packet to capture 65536 guarantees that the whole packet will be captured on all the link layers
                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                    1000))                                  // read timeout
            {
                // Check the link layer. We support only Ethernet for simplicity.
                if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                {
                    Console.WriteLine("This program works only on Ethernet networks.");
                    return;
                }

                // Compile the filter
                //TODO: Auch TCP untestützen! (vlt. "port 53 or port 853")
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and udp"))
                {
                    // Set the filter
                    //tshark -f "udp port 53" -Y "dns.qry.type == A and dns.flags.response == 0"
                    communicator.SetFilter(filter);
                }

                Console.WriteLine("Listening on " + device.Description + "...");

                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
            }

        }

        private static PacketDevice SelectDevice()
        {
            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return null;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);

            return allDevices[deviceIndex - 1]; ;
        }

        // from https://github.com/PcapDotNet/Pcap.Net/wiki/Pcap.Net-Tutorial-Interpreting-the-packets
        private static void InterpretPacketSample()
        {
            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);

            // Take the selected adapter
            PacketDevice selectedDevice = allDevices[deviceIndex - 1];

            // Open the device
            using (PacketCommunicator communicator = selectedDevice.Open(
                    65536,                                  // portion of the packet to capture 65536 guarantees that the whole packet will be captured on all the link layers
                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                    1000))                                  // read timeout
            {
                // Check the link layer. We support only Ethernet for simplicity.
                if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                {
                    Console.WriteLine("This program works only on Ethernet networks.");
                    return;
                }

                // Compile the filter
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and udp"))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }

                Console.WriteLine("Listening on " + selectedDevice.Description + "...");

                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        // Callback function invoked by libpcap for every incoming packet
        private static void PacketHandler(Packet packet)
        {
            IpV4Datagram ip = packet.Ethernet.IpV4;
            //TODO: statt udp oder tcp eher transport
            UdpDatagram udp = ip.Udp;
            DnsDatagram dns = udp.Dns;

            Console.Write("(" + packet.Timestamp.ToString("yyyy:MM:dd hh:mm:ss.fff") + ")  ");
            Console.Write(dns.IsQuery ? "Query: " : "Response: ");
            Console.Write(ip.Source + ":" + udp.SourcePort + "  ->  ");
            Console.WriteLine(ip.Destination + ":" + udp.DestinationPort);

            //TODO: Hier irgendwie Domainnamen rauskriegen
            foreach (var query in dns.Queries)
            {
                Console.WriteLine("\tQuery:" + query.DomainName);
            }
            foreach (var answer in dns.Answers)
            {
                Console.WriteLine("\tAnswer:" + answer.DomainName);
            }
            Console.WriteLine();
        }
    }
}