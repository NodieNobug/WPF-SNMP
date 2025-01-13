using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using SnmpSharpNet;
using System.Windows.Threading;
namespace SNMPManager
{
    public partial class MainWindow : Window
    {
        private SimpleSnmp snmp;

        private SnmpNode selectedNode;

        public MainWindow()
        {
            InitializeComponent();

            // 初始化SNMP连接
            snmp = new SimpleSnmp("192.168.56.1", "public");


            if (!snmp.Valid)
            {
                responseTextBox.Text = "SNMP连接信息无效";
                return;
            }

            // system
            SnmpNode root = new SnmpNode("MIB-2", "1.3.6.1");
            SnmpNode systemNode = new SnmpNode("System", "1.3.6.1.2.1.1");
            root.Children.Add(systemNode);
            SnmpNode sysDescrNode = new SnmpNode("SysDescr", "1.3.6.1.2.1.1.1.0");
            SnmpNode sysObjectID = new SnmpNode("SysObjectID", "1.3.6.1.2.1.1.2.0");
            SnmpNode sysUpTime = new SnmpNode("SysUptime", "1.3.6.1.2.1.1.3.0");
            SnmpNode sysContact = new SnmpNode("SysContact", "1.3.6.1.2.1.1.4.0");
            SnmpNode sysName = new SnmpNode("SysName", "1.3.6.1.2.1.1.5.0");
            SnmpNode sysLocation = new SnmpNode("SysLocation", "1.3.6.1.2.1.1.6.0");
            SnmpNode sysService = new SnmpNode("SysService", "1.3.6.1.2.1.1.7.0");
            systemNode.Children.Add(sysDescrNode);
            systemNode.Children.Add(sysObjectID);
            systemNode.Children.Add(sysUpTime);
            systemNode.Children.Add(sysContact);
            systemNode.Children.Add(sysName);
            systemNode.Children.Add(sysLocation);
            systemNode.Children.Add(sysService);


            //interfaces
            //累死,,,,,
            SnmpNode interfacesNode = new SnmpNode("Interfaces", "1.3.6.1.2.1.2");
            root.Children.Add(interfacesNode);
            //开始往里面加内容
            SnmpNode ifNumber = new SnmpNode("ifNumber", "1.3.6.1.2.1.2.1.0");
            SnmpNode ifTable = new SnmpNode("ifTable", "1.3.6.1.2.1.2.2.0");
            SnmpNode ifEntry = new SnmpNode("ifEntry", "1.3.6.1.2.1.2.2.1.0");

            interfacesNode.Children.Add(ifNumber);
            interfacesNode.Children.Add(ifTable);
            ifTable.Children.Add(ifEntry);
            Dictionary<string, string> formatMap_ipEntry = new Dictionary<string, string>
                {
               
                {"1.3.6.1.2.1.2.2.1.1.0", "ifIndex"},
                {"1.3.6.1.2.1.2.2.1.2.0", "ifDescr"},
                {"1.3.6.1.2.1.2.2.1.3.0", "ifType"},
                {"1.3.6.1.2.1.2.2.1.4.0", "ifMtu"},
                {"1.3.6.1.2.1.2.2.1.5.0", "ifSpeed"},
                {"1.3.6.1.2.1.2.2.1.6.0", "ifPhyAddress"},
                {"1.3.6.1.2.1.2.2.1.7.0", "ifAdminStatus"},
                {"1.3.6.1.2.1.2.2.1.8.0", "ifOperStatus"},
                {"1.3.6.1.2.1.2.2.1.9.0", "ifLastChange"},
                {"1.3.6.1.2.1.2.2.1.10.0", "ifInOctets"},
                {"1.3.6.1.2.1.2.2.1.11.0", "ifInUcastPkts"},
                {"1.3.6.1.2.1.2.2.1.12.0", "ifInNUcastPkts"},
                {"1.3.6.1.2.1.2.2.1.13.0", "ifInDiscards"},
                {"1.3.6.1.2.1.2.2.1.14.0", "ifnErrors"},
                {"1.3.6.1.2.1.2.2.1.15.0", "ifnUnknowProtos"},
                {"1.3.6.1.2.1.2.2.1.16.0", "ifOutOctets"},
                {"1.3.6.1.2.1.2.2.1.17.0", "ifOutUcastPkts"},
                {"1.3.6.1.2.1.2.2.1.18.0", "ifOutDiscards"},
                {"1.3.6.1.2.1.2.2.1.19.0", "ifOutErrors"},
                {"1.3.6.1.2.1.2.2.1.20.0", "ifInErrors"},
                {"1.3.6.1.2.1.2.2.1.21.0", "ifOutQlen"},
                {"1.3.6.1.2.1.2.2.1.22.0", "ifSpecific"}
                };

            // 遍历 formatMap 中的键值对，将每个节点添加到 interfacesNode
            foreach (var entry in formatMap_ipEntry)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key;
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                ifEntry.Children.Add(node);
            }
            //at
            //累死,,,,,
            SnmpNode at = new SnmpNode("at", "1.3.6.1.2.1.3");
            root.Children.Add(at);
            SnmpNode atTable = new SnmpNode("atTable", "1.3.6.1.2.1.3.1");
            at.Children.Add(atTable);
            SnmpNode atEntry = new SnmpNode("atEntry", "1.3.6.1.2.1.3.1.1");
            atTable.Children.Add(atEntry);

            SnmpNode atlfIndex = new SnmpNode("atlfIndex", "1.3.6.1.2.1.3.1.1.1.0");
            SnmpNode atPhysAddress = new SnmpNode("atPhysAddress", "1.3.6.1.2.1.3.1.1.2.0");
            SnmpNode atNetAddress = new SnmpNode("atNetAddress", "1.3.6.1.2.1.3.1.1.3.0");
            atEntry.Children.Add(atlfIndex);
            atEntry.Children.Add(atPhysAddress);
            atEntry.Children.Add(atNetAddress);


            //ip
            //累死...
            SnmpNode ip = new SnmpNode("ip", "1.3.6.1.2.1.4");
            root.Children.Add(ip);
            Dictionary<string, string> formatMap_ip = new Dictionary<string, string>
                 {
    {"1.3.6.1.2.1.4.1", "ipForwarding"},
    {"1.3.6.1.2.1.4.2", "ipDefaultTTL"},
    {"1.3.6.1.2.1.4.3", "ipInReceives"},
    {"1.3.6.1.2.1.4.4", "ipInHdrErrors"},
    {"1.3.6.1.2.1.4.5", "ipInAddrErrors"},
    {"1.3.6.1.2.1.4.6", "ipForwDatagrams"},
    {"1.3.6.1.2.1.4.7", "ipInInknowProtos"},
    {"1.3.6.1.2.1.4.8", "IpInDiscards"},
    {"1.3.6.1.2.1.4.9", "ipInDelivers"},
    {"1.3.6.1.2.1.4.10", "ipOutRequests"},
    {"1.3.6.1.2.1.4.11", "ipOutDiscards"},
    {"1.3.6.1.2.1.4.12", "ipOutNoRoutes"},
    {"1.3.6.1.2.1.4.13", "ipReasmTimeout"},
    {"1.3.6.1.2.1.4.14", "ipReasmReqds"},
    {"1.3.6.1.2.1.4.15", "ipReasmOKs"},
    {"1.3.6.1.2.1.4.16", "ipReasmFails"},
    {"1.3.6.1.2.1.4.17", "ipFragOKs"},
    {"1.3.6.1.2.1.4.18", "ipFragFails"},
    {"1.3.6.1.2.1.4.19", "ipFragCreates"}
};

            foreach (var entry in formatMap_ip)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key+".0";
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                ip.Children.Add(node);
            }

            SnmpNode ipAddrTable = new SnmpNode("ipAddrTable", "1.3.6.1.2.1.4.20");
            ip.Children.Add(ipAddrTable);
            SnmpNode ipAddrEntry = new SnmpNode("ipAddrEntry", "1.3.6.1.2.1.4.20.1");
            ipAddrTable.Children.Add(ipAddrEntry);

            // 创建一个包含接口相关节点 OID 和名称的字典
            Dictionary<string, string> formatMap_ipAddrEntry = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.4.20.1.1", "ipAdEntAddr"},
    {"1.3.6.1.2.1.4.20.1.2", "ipAdEntIfIndex"},
    {"1.3.6.1.2.1.4.20.1.3", "ipAdEntNetMask"},
    {"1.3.6.1.2.1.4.20.1.4", "ipAdEntBcastAddr"},
    {"1.3.6.1.2.1.4.20.1.5", "ipAdEntReasmMaxSize"}
};

            foreach (var entry in formatMap_ipAddrEntry)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                ipAddrEntry.Children.Add(node);
            }
            //ipRouteTable开始
            SnmpNode ipRouteTable = new SnmpNode("ipRouteTable", "1.3.6.1.2.1.4.21");
            ip.Children.Add(ipRouteTable);
            SnmpNode ipRouteEntry = new SnmpNode("ipRouteEntry", "1.3.6.1.2.1.4.21.1");
            ipRouteTable.Children.Add(ipRouteEntry);
            // 创建一个包含接口相关节点 OID 和名称的字典
            Dictionary<string, string> formatMap_ipRouteEntry = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.4.21.1.1", "ipRouteDest"},
    {"1.3.6.1.2.1.4.21.1.2", "ipRouteIfIndex"},
    {"1.3.6.1.2.1.4.21.1.3", "ipRouteMetric1"},
    {"1.3.6.1.2.1.4.21.1.4", "ipRouteMetric2"},
    {"1.3.6.1.2.1.4.21.1.5", "ipRouteMetric3"},
    {"1.3.6.1.2.1.4.21.1.6", "ipRouteMetric4"},
    {"1.3.6.1.2.1.4.21.1.7", "ipRouteNextHop"},
    {"1.3.6.1.2.1.4.21.1.8", "ipRouteType"},
    {"1.3.6.1.2.1.4.21.1.9", "ipRouteProto"},
    {"1.3.6.1.2.1.4.21.1.10", "ipRouteAge"},
    {"1.3.6.1.2.1.4.21.1.11", "ipRouteMask"},
    {"1.3.6.1.2.1.4.21.1.12", "ipRouteMetric5"},
    {"1.3.6.1.2.1.4.21.1.13", "ipRouteInfo"}
};

            foreach (var entry in formatMap_ipRouteEntry)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                ipRouteEntry.Children.Add(node);
            }

            //ipNet开始
            SnmpNode ipNetToMediaTable = new SnmpNode("ipNetToMediaTable", "1.3.6.1.2.1.4.22");
            ip.Children.Add(ipNetToMediaTable);
            SnmpNode ipNetToMediaEntry = new SnmpNode("ipNetToMediaEntry", "1.3.6.1.2.1.4.22.1");
            ipNetToMediaTable.Children.Add(ipNetToMediaEntry);
            // 创建一个包含接口相关节点 OID 和名称的字典
            Dictionary<string, string> formatMap_ipNetToMediaEntry = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.4.22.1.1", "ipNetToMediaIfIndex"},
    {"1.3.6.1.2.1.4.22.1.2", "ipNetToMediaPhysAddress"},
    {"1.3.6.1.2.1.4.22.1.3", "ipNetToMediaNetAddress"},
    {"1.3.6.1.2.1.4.22.1.4", "ipNetToMediaType"}
};

            foreach (var entry in formatMap_ipNetToMediaEntry)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
               ipNetToMediaEntry.Children.Add(node);
            }
            SnmpNode ipRoutingDiscards = new SnmpNode("ipRoutingDiscards", "1.3.6.1.2.1.4.23");
            ip.Children.Add(ipRoutingDiscards);

            //icmp
            //累死...
            SnmpNode icmp = new SnmpNode("icmp", "1.3.6.1.2.1.5");
            root.Children.Add(icmp);
            // 创建一个包含 ICMP 相关节点 OID 和名称的字典
            Dictionary<string, string> formatMap_icmp = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.5.1", "icmpInMsgs"},
    {"1.3.6.1.2.1.5.2", "icmpInErrors"},
    {"1.3.6.1.2.1.5.3", "icmpInDestUnreachs"},
    {"1.3.6.1.2.1.5.4", "icmpInTimeExcds"},
    {"1.3.6.1.2.1.5.5", "icmpInParmProbes"},
    {"1.3.6.1.2.1.5.6", "icmpInSrcQuenchs"},
    {"1.3.6.1.2.1.5.7", "icmpInRedirects"},
    {"1.3.6.1.2.1.5.8", "icmpInEchos"},
    {"1.3.6.1.2.1.5.9", "icmpInEchoReps"},
    {"1.3.6.1.2.1.5.10", "icmpInTimestamps"},
    {"1.3.6.1.2.1.5.11", "icmpInTimestampReps"},
    {"1.3.6.1.2.1.5.12", "icmpInAddrMasks"},
    {"1.3.6.1.2.1.5.13", "icmpInAddrMaskReps"},
    {"1.3.6.1.2.1.5.14", "icmpOutMsgs"},
    {"1.3.6.1.2.1.5.15", "icmpOutErrors"},
    {"1.3.6.1.2.1.5.16", "icmpOutDestUnreachs"},
    {"1.3.6.1.2.1.5.17", "icmpOutTimeExcds"},
    {"1.3.6.1.2.1.5.18", "icmpOutParmProbes"},
    {"1.3.6.1.2.1.5.19", "icmpOutSrcQuenchs"},
    {"1.3.6.1.2.1.5.20", "icmpOutRedirects"},
    {"1.3.6.1.2.1.5.21", "icmpOutEchos"},
    {"1.3.6.1.2.1.5.22", "icmpOutEchoReps"},
    {"1.3.6.1.2.1.5.23", "icmpOutTimestamps"},
    {"1.3.6.1.2.1.5.24", "icmpOutTimestampReps"},
    {"1.3.6.1.2.1.5.25", "icmpOutAddrMasks"},
    {"1.3.6.1.2.1.5.26", "icmpOutAddrMaskReps"}
};

            foreach (var entry in formatMap_icmp)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                icmp.Children.Add(node);
            }


            //tcp
            //累死
            SnmpNode tcp = new SnmpNode("tcp", "1.3.6.1.2.1.6");
            root.Children.Add(tcp);
            // 创建一个包含 TCP 相关节点 OID 和名称的字典
            Dictionary<string, string> formatMap_tcp = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.6.1", "tcpRtoAlgorithm"},
    {"1.3.6.1.2.1.6.2", "tcpRtoMin"},
    {"1.3.6.1.2.1.6.3", "tcpRtoMax"},
    {"1.3.6.1.2.1.6.4", "tcpMaxConn"},
    {"1.3.6.1.2.1.6.5", "tcpActiveOpens"},
    {"1.3.6.1.2.1.6.6", "tcpPassiveOpens"},
    {"1.3.6.1.2.1.6.7", "tcpAttemptFails"},
    {"1.3.6.1.2.1.6.8", "tcpEstabResets"},
    {"1.3.6.1.2.1.6.9", "tcpCurrEstab"},
    {"1.3.6.1.2.1.6.10", "tcpInSegs"},
    {"1.3.6.1.2.1.6.11", "tcpOutSegs"},
    {"1.3.6.1.2.1.6.12", "tcpRetransSegs"}
};

            foreach (var entry in formatMap_tcp)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                tcp.Children.Add(node);
            }


            SnmpNode tcpConnTable = new SnmpNode("tcpConnTable", "1.3.6.1.2.1.6.13");
            tcp.Children.Add(tcpConnTable);
            SnmpNode tcpConnEntry = new SnmpNode("tcpConnEntry", "1.3.6.1.2.1.6.13.1");
            tcpConnTable.Children.Add(tcpConnEntry);
            // 创建一个包含 TCP 连接状态相关节点 OID 和名称的字典
            Dictionary<string, string> format_TcpEntry = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.6.13.1.1", "tcpConnState"},
    {"1.3.6.1.2.1.6.13.1.2", "tcpConnLocalAddress"},
    {"1.3.6.1.2.1.6.13.1.3", "tcpConnLocalPort"},
    {"1.3.6.1.2.1.6.13.1.4", "tcpConnRemAddress"},
    {"1.3.6.1.2.1.6.13.1.5", "tcpConnRemPort"}
};

            foreach (var entry in format_TcpEntry)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                tcpConnEntry.Children.Add(node);
            }

            SnmpNode tcpInerrs = new SnmpNode("tcpInerrs", "1.3.6.1.2.1.6.14");
            tcp.Children.Add(tcpInerrs);
            SnmpNode tcpOutRsts = new SnmpNode("tcpOutRsts", "1.3.6.1.2.1.6.15");
            tcp.Children.Add(tcpOutRsts);

            //udp
            //累死..
            SnmpNode udp = new SnmpNode("udp", "1.3.6.1.2.1.7");
            root.Children.Add(udp);
            // 创建一个包含 UDP 相关节点 OID 和名称的字典
            Dictionary<string, string> formatMapUdp = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.7.1", "udpInDatagrams"},
    {"1.3.6.1.2.1.7.2", "udpNoPorts"},
    {"1.3.6.1.2.1.7.3", "udpInErrors"},
    {"1.3.6.1.2.1.7.4", "udpOutErrors"}
};

            foreach (var entry in formatMapUdp)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                udp.Children.Add(node);
            }


            SnmpNode udpTable = new SnmpNode("udpTable", "1.3.6.1.2.1.7.5");
            udp.Children.Add(udpTable);
            SnmpNode udpEntry = new SnmpNode("udpEntry", "1.3.6.1.2.1.7.5.1");
            udpTable.Children.Add(udpEntry);

            SnmpNode udpLocalAddress = new SnmpNode("udpLocalAddress", "1.3.6.1.2.1.7.5.1.1.0");
            udpEntry.Children.Add(udpLocalAddress);

            SnmpNode udpLocalPort = new SnmpNode("udpLocalPort", "1.3.6.1.2.1.7.5.1.2.0");
            udpEntry.Children.Add(udpLocalPort);

            //egp
            //累死...
            SnmpNode egp = new SnmpNode("egp", "1.3.6.1.2.1.8");
            root.Children.Add(egp);
            // 创建一个包含 EGP 相关节点 OID 和名称的字典
            Dictionary<string, string> formatMapEgp = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.8.1", "egpInMsgs"},
    {"1.3.6.1.2.1.8.2", "egpInErrors"},
    {"1.3.6.1.2.1.8.3", "egpOutMsgs"},
    {"1.3.6.1.2.1.8.4", "egpOutErrors"}
};

            foreach (var entry in formatMapEgp)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                egp.Children.Add(node);
            }

            SnmpNode egpNeighTable = new SnmpNode("egpNeighTable", "1.3.6.1.2.1.8.5");
            egp.Children.Add(egpNeighTable);
            SnmpNode egpNeighEntry = new SnmpNode("egpNeighEntry", "1.3.6.1.2.1.8.5.1");
            egpNeighTable.Children.Add(egpNeighEntry);
            // 创建一个包含 EGP 邻居相关节点 OID 和名称的字典
            Dictionary<string, string> formatMapEgpNeigh = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.8.5.1.1", "egpNeighState"},
    {"1.3.6.1.2.1.8.5.1.2", "egpNeighAddr"},
    {"1.3.6.1.2.1.8.5.1.3", "egpNeighAs"},
    {"1.3.6.1.2.1.8.5.1.4", "egpNeighInMsgs"},
    {"1.3.6.1.2.1.8.5.1.5", "egpNeighInErrs"},
    {"1.3.6.1.2.1.8.5.1.6", "egpNeighOutMsgs"},
    {"1.3.6.1.2.1.8.5.1.7", "egpNeighOutErrs"},
    {"1.3.6.1.2.1.8.5.1.8", "egpNeighInErrMsgs"},
    {"1.3.6.1.2.1.8.5.1.9", "egpNeighOutErrMsgs"},
    {"1.3.6.1.2.1.8.5.1.10", "egpNeighStateUps"},
    {"1.3.6.1.2.1.8.5.1.11", "egpNeighStateDowns"},
    {"1.3.6.1.2.1.8.5.1.12", "egpNeighIntervalHello"},
    {"1.3.6.1.2.1.8.5.1.13", "egpNeighIntervalPoll"},
    {"1.3.6.1.2.1.8.5.1.14", "egpNeighMode"},
    {"1.3.6.1.2.1.8.5.1.15", "egpNeighEventTrigger"}
};

            foreach (var entry in formatMapEgpNeigh)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
                egpNeighEntry.Children.Add(node);
            }
            SnmpNode egpAs = new SnmpNode("egpAs", "1.3.6.1.2.1.8.6");
            egp.Children.Add(egpAs);

            //transmission
            SnmpNode transmission = new SnmpNode("transmission", "1.3.6.1.2.1.10");
            root.Children.Add(transmission);

            //SNMP
            //已si，后面的host不想写了《直接原地崩溃》
            SnmpNode mysnmp = new SnmpNode("snmp", "1.3.6.1.2.1.11");
            root.Children.Add(mysnmp);
            // 创建一个包含 SNMP 统计相关节点 OID 和名称的字典
            Dictionary<string, string> formatMapSnmpStats = new Dictionary<string, string>
{
    {"1.3.6.1.2.1.11.1", "snmpInPkts"},
    {"1.3.6.1.2.1.11.2", "snmpOutPkts"},
    {"1.3.6.1.2.1.11.3", "snmpInBadVersions"},
    {"1.3.6.1.2.1.11.4", "snmpInBadCommunityNames"},
    {"1.3.6.1.2.1.11.5", "snmpInBadCommunityUses"},
    {"1.3.6.1.2.1.11.6", "snmpInASNParseErrs"},
    {"1.3.6.1.2.1.11.8", "snmpInTooBigs"},
    {"1.3.6.1.2.1.11.9", "snmpInNoSuchNames"},
    {"1.3.6.1.2.1.11.10", "snmpInBadValues"},
    {"1.3.6.1.2.1.11.11", "snmpInReadOnlys"},
    {"1.3.6.1.2.1.11.12", "snmpInGenErrs"},
    {"1.3.6.1.2.1.11.13", "snmpInTotalReqVars"},
    {"1.3.6.1.2.1.11.14", "snmpInTotalSetVars"},
    {"1.3.6.1.2.1.11.15", "snmpInGetRequests"},
    {"1.3.6.1.2.1.11.16", "snmpInGetNexts"},
    {"1.3.6.1.2.1.11.17", "snmpInSetRequests"},
    {"1.3.6.1.2.1.11.18", "snmpInGetResponses"},
    {"1.3.6.1.2.1.11.19", "snmpInTraps"},
    {"1.3.6.1.2.1.11.20", "snmpOutTooBigs"},
    {"1.3.6.1.2.1.11.21", "snmpOutNoSuchNames"},
    {"1.3.6.1.2.1.11.22", "snmpOutBadValues"},
    {"1.3.6.1.2.1.11.24", "snmpOutGenErrs"},
    {"1.3.6.1.2.1.11.25", "snmpOutGetRequests"},
    {"1.3.6.1.2.1.11.26", "snmpOutGetNexts"},
    {"1.3.6.1.2.1.11.27", "snmpOutSetRequests"},
    {"1.3.6.1.2.1.11.28", "snmpOutGetResponses"},
    {"1.3.6.1.2.1.11.29", "snmpOutTraps"},
    {"1.3.6.1.2.1.11.30", "snmpEnableAuthenTraps"}
};

            foreach (var entry in formatMapSnmpStats)
            {
                string nodeName = entry.Value;
                string nodeOid = entry.Key + ".0"; // 添加 .0
                SnmpNode node = new SnmpNode(nodeName, nodeOid);
               mysnmp.Children.Add(node);
            }



            // 将树形结构绑定到TreeView
            snmpTreeView.ItemsSource = new ObservableCollection<SnmpNode> { root };
        }

        private void GetButton_Click(object sender, RoutedEventArgs e)
        {
            PerformSnmpOperation(PduType.Get);
        }

        private void SetButton_Click(object sender, RoutedEventArgs e)
        {
            PerformSnmpOperation(PduType.Set);
        }

        private void GetBulkButton_Click(object sender, RoutedEventArgs e)
        {
            PerformSnmpOperation(PduType.GetBulk);
        }

        private void GetNextButton_Click(object sender, RoutedEventArgs e)
        {
            PerformSnmpOperation(PduType.GetNext);
        }

        private void WalkButton_Click(object sender, RoutedEventArgs e)
        {
            string setValue = setValueTextBox.Text;

            // 执行SNMP操作
            Dictionary<Oid, AsnType> result = null;

            setValueTextBox.Text = "";
            responseTextBox.Text = "";
            result = snmp.Walk(SnmpVersion.Ver2, selectedNode.Oid);
            foreach (var item in result)
            {
                oidTextBox.Text = item.Key.ToString();

                responseTextBox.Text += item.Value.ToString() + "\n";
            }
        }
        private bool IsChinese(string input)
        {
            return Regex.IsMatch(input, @"[\u4e00-\u9fa5]");
        }




        private void PerformSnmpOperation(PduType pduType)
        {
            if (selectedNode == null)
            {
                responseTextBox.Text = "请先选择一个节点";
                return;
            }

            // 获取用户输入的设置值
            string setValue = setValueTextBox.Text;

            //定义result
            Dictionary<Oid, AsnType> result = null;

            switch (pduType)
            {
                case PduType.Get:
                    setValueTextBox.Text = "";
                    responseTextBox.Text = "";
                    Pdu pdu = new Pdu();
                    pdu.Type = PduType.Get;
                    pdu.VbList.Add(new Oid(selectedNode.Oid));
                    result = snmp.Get(SnmpVersion.Ver2, pdu);
                    oidTextBox.Text = selectedNode.Oid;
                    foreach (var item in result)
                    {
                        responseTextBox.Text = item.Value.ToString();
                    }
                    break;
                case PduType.Set:
                    setValueTextBox.Text = "";
                    responseTextBox.Text = "";
                    if (string.IsNullOrEmpty(setValue))
                    {
                        responseTextBox.Text = "设置值不能为空";
                        return;
                    }
                    Pdu setPdu = new Pdu();
                    setPdu.Type = PduType.Set;
                    setPdu.VbList.Add(new Oid(selectedNode.Oid), new OctetString(setValue));
                    result = snmp.Set(SnmpVersion.Ver1, setPdu);
                   


                    foreach (var item in result)
                    {
                        responseTextBox.Text = item.Value.ToString();

                     
                    }

                    break;
                case PduType.GetBulk:
                    //请注意MIB-Browser中为了避免网络拥塞和提高响应速度，默认只展示10条。本程序运行结果为最终全部最终版本
                    setValueTextBox.Text = "";
                    responseTextBox.Text = "";

                    Pdu getBulkPdu = new Pdu();
                    getBulkPdu.Type = PduType.GetBulk;
                    getBulkPdu.VbList.Add(new Oid(selectedNode.Oid));
                    result = snmp.GetBulk(getBulkPdu);
                    foreach (var item in result)
                    {
  
                        responseTextBox.Text += item.Value.ToString() + "\n";
                    }
                    break;

                case PduType.GetNext:
                    setValueTextBox.Text = "";
                    responseTextBox.Text = "";
                    Pdu getNextPdu = new Pdu();
                    getNextPdu.Type = PduType.GetNext;
                    getNextPdu.VbList.Add(new Oid(selectedNode.Oid));
                    result = snmp.GetNext(SnmpVersion.Ver2, getNextPdu);
                    foreach (var item in result)
                    {
                        oidTextBox.Text = item.Key.ToString();
                        responseTextBox.Text = item.Value.ToString();
                    }


                    Console.WriteLine(result);
                    break;
               
                default:
                    throw new ArgumentOutOfRangeException(nameof(pduType), pduType, null);
            }

        }

        private void snmpTreeView_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            selectedNode = e.NewValue as SnmpNode;
            oidTextBox.Text = selectedNode.Oid.ToString();
        }


    }

    public class SnmpNode
    {
        public string Name { get; set; }
        public string Oid { get; set; }
        public ObservableCollection<SnmpNode> Children { get; set; }

        public SnmpNode(string name, string oid)
        {
            Name = name;
            Oid = oid;
            Children = new ObservableCollection<SnmpNode>();
        }
     
    }
}
