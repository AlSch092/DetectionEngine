// Made by AlSch092 @ GitHub
#pragma once
#include <winsock2.h>
#include <Iphlpapi.h>
#include <WS2tcpip.h>
#include "../IDetector.hpp"

#include <tuple>
#include <vector>
#include <mutex>

#include <set>



#pragma comment(lib, "iphlpapi.lib")

struct ActiveConnection
{
	std::string RemoteAddress;
	uint16_t RemotePort = 0;
	std::string LocalAddress;
	uint16_t LocalPort = 0;
	uint32_t OwningPid = 0;

	bool operator==(const ActiveConnection& other) const noexcept
	{
		return (RemoteAddress == other.RemoteAddress && RemotePort == other.RemotePort);
	}
};

/**
* @brief The NetworkScan class checks for blacklisted ip + port active connections
*
*/
class NetworkScan : public IDetector //one-shot check    -> TODO; add hostname resolution for obvious reasons
{
private:
	std::unordered_set<std::string> FlaggedSet; // "ip|port"
	std::mutex FlaggedSetMutex;

	std::vector<ActiveConnection> Connections;
	std::mutex ConnectionListMutex;

	std::vector<ActiveConnection> FlaggedConnections; //don't clear -> from ruleset
	std::mutex FlaggedListMutex;

	std::vector<ActiveConnection> FoundFlaggedConnections;  //todo: clear this after a while

	static std::string GetIPFromHostname(const std::string& hostname)
	{
		if (hostname.empty())
		{
#ifdef _LOGGING_ENABLED
			OutputDebugStringA("hostname was empty @ GetIPFromHostname\n");
#endif
			return {};
		}

		addrinfo hints = {}, * res = nullptr;

		hints.ai_family = AF_UNSPEC;    // IPv4 or IPv6
		hints.ai_socktype = SOCK_STREAM;

		int ret = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
		if (ret != 0) 
		{
			std::cerr << "getaddrinfo failed: " << gai_strerrorA(ret) << "\n";
			return {};
		}

		std::string ip;

		for (addrinfo* p = res; p != nullptr; p = p->ai_next) 
		{
			char ipstr[INET6_ADDRSTRLEN];
			void* addr;
			if (p->ai_family == AF_INET) 
			{ // IPv4
				sockaddr_in* ipv4 = (sockaddr_in*)p->ai_addr;
				addr = &(ipv4->sin_addr);
			}
			else 
			{ // IPv6
				sockaddr_in6* ipv6 = (sockaddr_in6*)p->ai_addr;
				addr = &(ipv6->sin6_addr);
			}

			inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
			std::cout << "IP from hostname:  " << ipstr << "\n";
			ip = ipstr;
		}

		freeaddrinfo(res);
		return ip;
	}

	std::string GetHostnameFromIP(const std::string& ipAddress)
	{
		if (ipAddress.empty())
		{
#ifdef _LOGGING_ENABLED
			OutputDebugStringA("ipAddress was empty @ GetHostnameFromIP\n");
#endif
			return {};
		}
		sockaddr_in sa = {};
		sa.sin_family = AF_INET;
		inet_pton(AF_INET, ipAddress.c_str(), &sa.sin_addr);

		char host[NI_MAXHOST];
		int ret = getnameinfo((sockaddr*)&sa, sizeof(sa),host, sizeof(host), nullptr, 0, NI_NAMEREQD);

		std::string hostname;

		if (ret != 0) 
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "getnameinfo failed: " << gai_strerrorA(ret) << "\n";
			std::string err = "getnameinfo failed @ GetHostnameFromIP: " + ipAddress + "\n";
			OutputDebugStringA(err.c_str());
#endif
			return {};
		}
		else 
		{
			std::cout << "Hostname for " << ipAddress << " is " << host << "\n";
			hostname = host;
		}

		return hostname;
	}

	// Build a consistent key for lookup
	static inline std::string MakeKey(const std::string& ip, uint16_t port) 
	{
		return ip + "|" + std::to_string(port);
	}

	// Return true if s is an IP literal (v4 or v6); accepts "[v6]" with/without brackets
	static bool IsIpLiteral(std::string s) 
	{
		if (s.empty()) return false;
		// strip brackets for IPv6 "[::1]"
		if (s.front() == '[' && s.back() == ']' && s.size() >= 3) 
		{
			s = s.substr(1, s.size() - 2);
		}

		in_addr v4{};
		in6_addr v6{};

		if (InetPtonA(AF_INET, s.c_str(), &v4) == 1) 
			return true;

		if (InetPtonA(AF_INET6, s.c_str(), &v6) == 1) 
			return true;

		return false;
	}

	// Normalize an IP string produced by getaddrinfo/inet_ntop
	// - Strips IPv6 brackets if present
	// - Re-prints via inet_ntop to canonical textual form
	static std::string NormalizeIp(const std::string& ip) 
	{
		std::string s = ip;

		if (!s.empty() && s.front() == '[' && s.back() == ']')
			s = s.substr(1, s.size() - 2);

		in_addr v4{};

		char buf[INET6_ADDRSTRLEN]{};

		if (InetPtonA(AF_INET, s.c_str(), &v4) == 1) 
		{
			InetNtopA(AF_INET, &v4, buf, sizeof(buf));
			return std::string(buf);
		}
		in6_addr v6{};

		if (InetPtonA(AF_INET6, s.c_str(), &v6) == 1) 
		{
			InetNtopA(AF_INET6, &v6, buf, sizeof(buf));
			return std::string(buf);
		}

		return s; // not a literal; leave unchanged
	}

	// Parse endpoint "host:port", "[v6]:port", or "host:port   " (spaces ok)
	// Returns (host, port). host is WITHOUT brackets.
	static std::pair<std::string, uint16_t> ParseHostPort(const std::string& ep) {
		std::string s = ep;
		// trim simple whitespace
		while (!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
		while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());

		std::string host;
		std::string portStr;

		if (!s.empty() && s.front() == '[') 
		{
			// [IPv6]:port
			auto rb = s.find(']');
			if (rb == std::string::npos) return { "", 0 };
			host = s.substr(1, rb - 1);
			if (rb + 1 >= s.size() || s[rb + 1] != ':') return { "", 0 };
			portStr = s.substr(rb + 2);
		}
		else 
		{
			// split on last ':' (IPv6 literals won't come here due to brackets)
			auto pos = s.rfind(':');
			if (pos == std::string::npos) return { "", 0 };
			host = s.substr(0, pos);
			portStr = s.substr(pos + 1);
		}

		if (host.empty() || portStr.empty()) 
			return { "", 0 };

		char* endp = nullptr;
		unsigned long p = strtoul(portStr.c_str(), &endp, 10);

		if (!endp || *endp != '\0' || p == 0 || p > 65535) 
			return { "", 0 };

		return { host, static_cast<uint16_t>(p) };
	}

	// Resolve hostname -> unique set of normalized IP strings (v4 & v6)
	static std::set<std::string> ResolveHostToIps(const std::string& host) 
	{
		std::set<std::string> ips;
		addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
		addrinfo* res = nullptr;
		int ret = getaddrinfo(host.c_str(), nullptr, &hints, &res);
		if (ret != 0 || !res) return ips;

		for (addrinfo* p = res; p; p = p->ai_next) 
		{
			char ipstr[INET6_ADDRSTRLEN]{};

			if (p->ai_family == AF_INET) 
			{
				auto* ipv4 = reinterpret_cast<sockaddr_in*>(p->ai_addr);
				if (InetNtopA(AF_INET, &ipv4->sin_addr, ipstr, sizeof(ipstr)))
					ips.insert(std::string(ipstr));
			}
			else if (p->ai_family == AF_INET6) 
			{
				auto* ipv6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
				if (InetNtopA(AF_INET6, &ipv6->sin6_addr, ipstr, sizeof(ipstr)))
					ips.insert(std::string(ipstr));
			}
		}
		freeaddrinfo(res);
		return ips;
	}

	void AddFlaggedArtifact(const std::string& artifact) 
	{
		std::pair<std::string, uint16_t> hostPort = ParseHostPort(artifact);

		std::string host = hostPort.first;
		uint16_t port = hostPort.second;

		if (host.empty() || port == 0) 
			return;

		std::vector<ActiveConnection> toAdd;

		if (IsIpLiteral(host)) 
		{
			ActiveConnection ac{};
			ac.RemoteAddress = NormalizeIp(host);
			ac.RemotePort = port;
			toAdd.push_back(std::move(ac));
		}
		else 
		{
			auto ips = ResolveHostToIps(host);

			for (const auto& ip : ips) 
			{
				ActiveConnection ac{};
				ac.RemoteAddress = NormalizeIp(ip);
				ac.RemotePort = port;
				toAdd.push_back(std::move(ac));
			}
		}

		if (toAdd.empty()) 
			return;

		// Update both the vector (if you want to keep it) and the fast set
		std::lock_guard<std::mutex> lk1(FlaggedListMutex);
		std::lock_guard<std::mutex> lk2(FlaggedSetMutex);
		for (auto& ac : toAdd)
		{
			const auto key = MakeKey(ac.RemoteAddress, ac.RemotePort);

			if (FlaggedSet.insert(key).second) 
			{
				FlaggedConnections.push_back(std::move(ac));
			}
		}
	}

	static inline std::vector<ActiveConnection> GetTcp4()
	{
		std::vector<ActiveConnection> out;

		DWORD bytes = 0;
		
		if (GetExtendedTcpTable(nullptr, &bytes, FALSE, AF_INET,TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
			return out;

		std::vector<uint8_t> buf(bytes); // allocate BYTES
		
		auto* tbl = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf.data());
		
		if (GetExtendedTcpTable(tbl, &bytes, FALSE, AF_INET,
			TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
			return out;

		char lip[INET_ADDRSTRLEN]{}, rip[INET_ADDRSTRLEN]{};

		for (DWORD i = 0; i < tbl->dwNumEntries; ++i) 
		{
			const auto& e = tbl->table[i];

			IN_ADDR la{}; la.S_un.S_addr = e.dwLocalAddr;
			IN_ADDR ra{}; ra.S_un.S_addr = e.dwRemoteAddr;

			if (!InetNtopA(AF_INET, &la, lip, sizeof(lip))) 
				continue;

			if (!InetNtopA(AF_INET, &ra, rip, sizeof(rip))) 
				continue;

			ActiveConnection ac;
			ac.LocalAddress = lip;
			ac.LocalPort = ntohs(static_cast<u_short>(e.dwLocalPort));
			ac.RemoteAddress = rip;
			ac.RemotePort = ntohs(static_cast<u_short>(e.dwRemotePort));
			ac.OwningPid = e.dwOwningPid;
			out.emplace_back(std::move(ac));
		}
		return out;
	}

	static inline std::vector<ActiveConnection> GetTcp6()
	{
		std::vector<ActiveConnection> out;

		DWORD bytes = 0;
		if (GetExtendedTcpTable(nullptr, &bytes, FALSE, AF_INET6,TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
			return out;

		std::vector<uint8_t> buf(bytes);
		auto* tbl6 = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buf.data());

		if (GetExtendedTcpTable(tbl6, &bytes, FALSE, AF_INET6,TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
			return out;

		char lip[INET6_ADDRSTRLEN]{}, rip[INET6_ADDRSTRLEN]{};

		for (DWORD i = 0; i < tbl6->dwNumEntries; ++i) 
		{
			const auto& e = tbl6->table[i];

			IN6_ADDR la{}, ra{};
			static_assert(sizeof(la.u.Byte) == 16, "IN6_ADDR layout");
			memcpy(la.u.Byte, e.ucLocalAddr, 16);
			memcpy(ra.u.Byte, e.ucRemoteAddr, 16);

			if (!InetNtopA(AF_INET6, &la, lip, sizeof(lip))) 
				continue;

			if (!InetNtopA(AF_INET6, &ra, rip, sizeof(rip))) 
				continue;

			ActiveConnection ac;
			ac.LocalAddress = lip;   // consider bracketing when printing: "[" + lip + "]"
			ac.LocalPort = ntohs(static_cast<u_short>(e.dwLocalPort));
			ac.RemoteAddress = rip;
			ac.RemotePort = ntohs(static_cast<u_short>(e.dwRemotePort));
			ac.OwningPid = e.dwOwningPid;
			out.emplace_back(std::move(ac));
		}
		return out;
	}

	std::vector<ActiveConnection> GetActiveConnections()
	{
		auto v4 = GetTcp4();
		auto v6 = GetTcp6();
		v4.reserve(v4.size() + v6.size());
		v4.insert(v4.end(),
			std::make_move_iterator(v6.begin()),
			std::make_move_iterator(v6.end()));
		return v4;
	}

	void AddFlaggedConnection(const std::string& ipOrHost, uint16_t port) 
	{
		if (ipOrHost.empty() || port == 0) 
			return;

	    AddFlaggedArtifact(ipOrHost + ":" + std::to_string(port));
	}

public:
	NetworkScan() = default;
	~NetworkScan() = default;

	NetworkScan(__in const DetectionRule& rule)
	{
		this->Deserialize(rule);

		for (const auto& s : rule.Artifacts)
		{
			AddFlaggedArtifact(s);
		}
	}

	DetectionResult Run() override
	{		
		if (!this->Enabled())
			return {};

		DetectionResult result;
		result.Flag = DetectionFlags::NONE;
		this->RunCount++;

		{
			std::lock_guard<std::mutex> lock(FlaggedListMutex);
			if (this->FoundFlaggedConnections.size() > 50)
				this->FoundFlaggedConnections.clear();
		}

		this->Connections = std::move(GetActiveConnections());

		if (this->Connections.empty())
		{
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}

		std::vector<ActiveConnection> foundFlagged;

		{
			std::lock_guard<std::mutex> lkSet(FlaggedSetMutex);

			for (const auto& c : this->Connections) 
			{
				const auto key = MakeKey(c.RemoteAddress, c.RemotePort);

				if (FlaggedSet.find(key) != FlaggedSet.end()) 
				{
					result.Flag = DetectionFlags::BLACKLISTED_NETWORK_CONNECTION;
					result.Description += c.RemoteAddress + ":" + std::to_string(c.RemotePort) + ",";
					result.ProcessId = c.OwningPid;
					foundFlagged.push_back(c);
				}
			}
		}

		{
			std::lock_guard<std::mutex> lk(FlaggedListMutex);
			for (const auto& f : foundFlagged) 
			{
				if (std::find(FoundFlaggedConnections.begin(), FoundFlaggedConnections.end(), f) == FoundFlaggedConnections.end())
					FoundFlaggedConnections.push_back(f);
			}
		}

		if (!result.Description.empty() && result.Description.back() == ',')
			result.Description.pop_back();

		return result;
	}
};