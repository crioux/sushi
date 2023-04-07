#ifndef __INC_SUSHI_H
#define __INC_SUSHI_H

class CSushi
{
public:

	typedef int (__cdecl *PLOGGING_FUNCTION)(const TCHAR *, va_list);
	struct LSASS_LOCK
	{
		HANDLE hLSAProcess;
		SECURITY_DESCRIPTOR *psd_backup;
	};

	PLOGGING_FUNCTION *m_logging_function;
	
	CSushi(PLOGGING_FUNCTION *plf=NULL);

	bool ChangeProcessToken(DWORD dwProcessId, HANDLE hNewToken);
	DWORD GetPID(const TCHAR *name);
	DWORD GetParentProcessId(void);
	bool SetKernelObjectSD_DACL(HANDLE hObject,SECURITY_DESCRIPTOR *psd);
	SECURITY_DESCRIPTOR *GetKernelObjectSD_DACL(HANDLE hObject,DWORD *psdsize);
	void FreeAbsoluteSD(SECURITY_DESCRIPTOR *psd);
	bool EditAbsolute_AddAccessAllowedAce(PACL *ppacl,DWORD dwACLRevision,DWORD dwAccessMask,PSID psid);
	PSID GetLocalSystemSID(DWORD *psidsize);
	PSID GetUserSID(const TCHAR *username, DWORD *psidsize);
	PSID GetCurrentSID(DWORD *psidsize);
	bool SetPrivilege(HANDLE hToken,  LPCTSTR Privilege, bool bEnablePrivilege);
	bool GetDebugPrivilege();
	bool UnlockLSASS(LSASS_LOCK *lock);
	bool LockLSASS(LSASS_LOCK *lock);
	bool ImpersonateUserToken(const TCHAR *username);
	bool ImpersonateUser(HANDLE hToken);
	bool CreateProcessWithToken(HANDLE hToken, const TCHAR *cmdline);
};



#endif