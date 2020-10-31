#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "Helper.h"
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <cstdio>
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996)
#pragma once
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

uHOST::uHOST(){};


void uHOST::BasicHostInfos() {
	//Declare a pointer to a FIXED INFO OBJECT CALLED
	//pFixedInfo, and a ULONG object called ulOutBufLen.
	//These variables are passed as parameters to the 
	//GetNetworkParams function. Also Creates a DWORD
	//variable dwRetVal(used for error checking)
	
	FIXED_INFO* pFixedInfo;
	IP_ADDR_STRING* pIPAddr;

	ULONG ulOutBufLen;
	DWORD dwRetVal;
	//The size of ulOutBufLen is not sufficient to hold
	//the information. See the next step
	pFixedInfo = (FIXED_INFO*)malloc(sizeof(FIXED_INFO));
	ulOutBufLen = sizeof(FIXED_INFO);
	//Make an initial call to GetNetworkParams to get
	//the size required for the ulOutBufLen variable
	//specifies a size sufficient for holding all the
	//data to pFixedInfo. This is a common programming
	//model for data structures and function of this
	//type.
	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pFixedInfo);
		pFixedInfo = (FIXED_INFO*)malloc(ulOutBufLen);
		if (pFixedInfo == NULL) {
			printf("Error allocating memory needed to call GetNetworkParams\n");
		}
	}

	//Make a second call to GetNetworkParams using general error checking and returning it's value
	//to the dword variable dwRetVal; used for more advanced checking.
	if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) != NO_ERROR) {
		printf("GetNetworkParams Failed with error%d\n", dwRetVal);
		if (pFixedInfo) {
			free(pFixedInfo);
		}
	}
	//If the call was successful access the data from the pFixedInfo data Structure.
	printf("Host Name : %s\n", pFixedInfo->HostName);
	if (pFixedInfo->DomainName == "") {
		printf("Domain Name : %s\n", pFixedInfo->DomainName);
	}
	printf("DNS Servers : %s\n", pFixedInfo->DnsServerList.IpAddress.String);
	pIPAddr = pFixedInfo->DnsServerList.Next;
	int i{ 0 };
	while (pIPAddr) {
		printf("%s\n", pIPAddr->IpAddress.String);
		pIPAddr = pIPAddr->Next;
		i++;
	};
}

void uHOST::BasicIPInfos() {
	int i{0};
	 /*Variables used by GetIpAddrTable*/
	PMIB_IPADDRTABLE pIPAddrTable;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;
	IN_ADDR IPAddr;

	/*Variables used to return error messages*/
	LPVOID lpMsgBuf;

	//Before Calling AddIpAddress we use GetIpAddrTable to get
	//an adapter to which we can add the IP.
	pIPAddrTable = (MIB_IPADDRTABLE*)MALLOC(sizeof(MIB_IPADDRTABLE));
	if (pIPAddrTable) {
		//Make an initial call to GetIpAddrTable to get the necessary size into the dwSize Variable
		if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
			FREE(pIPAddrTable);
			pIPAddrTable = (MIB_IPADDRTABLE*)MALLOC(dwSize);
		}
		if (pIPAddrTable == NULL) {
			printf("Memory allocation failed for GetIpAddrTable");
			exit(1);
		}
	}
	//Make a second call to GetIpAddrTable to get the actual data we want.
	if (dwRetVal = GetIpAddrTable(pIPAddrTable, &dwSize, 0) != NO_ERROR) {
		printf("GetIpAddrTable failed with error %d\n", dwRetVal);
		if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf, 0, NULL)) {
			printf("Error : %s", lpMsgBuf);
			LocalFree(lpMsgBuf);
		}
		exit(1);
	}
	printf("Number of Interfaces: %ld\n", pIPAddrTable->dwNumEntries);
	for (int i = 0; i < (int)pIPAddrTable->dwNumEntries; i++) {
		printf("\n\tInterface Index[%d]:\n", i, pIPAddrTable->table[i].dwIndex);
		IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[i].dwAddr;
		printf("IP Address[%d] : \t%s\n", i, inet_ntoa(IPAddr));
		IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[i].dwMask;
		printf("Subnet Mask[%d] : \t%s\n", i, inet_ntoa(IPAddr));
		IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[i].dwBCastAddr;
		//printf("Broadcast[%d] : \t%s (%ld%)\n", i, inet_ntoa(IPAddr), pIPAddrTable->table[i].dwBCastAddr);
		printf("Reassembly Size[%d] : \t%ld\n", i, pIPAddrTable->table[i].dwReasmSize);
		printf("Type and State[%d] : ", i);
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_PRIMARY) {
			printf("Primary IP Address\n");
		}
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_DYNAMIC) {
			printf("Dynamic IP Address\n");
		}
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_DISCONNECTED) {
			printf("Address is on disconnected interface\n");
		}
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_DELETED) {
			printf("Address is being deleted\n");
		}
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_TRANSIENT) {
			printf("Transient address\n");
		}
		printf("\n");
	}
	if (pIPAddrTable) {
		FREE(pIPAddrTable);
		pIPAddrTable = NULL;
	}
	exit(0);
}

