// D_DllLoader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

BOOL GetDebugPrivileges( void );

BOOL AttemptInjection( char* pszProcessName, char* pszModuleName )
{
	HANDLE hProcess = Remote::GetRemoteProcessHandleA( pszProcessName );

	if( hProcess == INVALID_HANDLE_VALUE )
	{
		printf( "No such handle!\n" );

		return FALSE;
	}

	printf( "Process Handle [0x%X][0x%X]\n", hProcess, GetProcessId( hProcess ) );

	char pszModuleTotalPathName[ MAX_PATH ];

	if( GetModuleFileNameA( GetModuleHandle( NULL ), pszModuleTotalPathName, MAX_PATH ) )
	{
		for(size_t i = strlen( pszModuleTotalPathName ); pszModuleTotalPathName[i] != '\\'; pszModuleTotalPathName[i] = 0,  i--){}
	}

	strcat_s( pszModuleTotalPathName, pszModuleName );

	BOOL bResult = threadInject::LoadLibraryMainThread( hProcess, pszModuleTotalPathName );

	if( !bResult )
	{
		printf( "Failed LoadLibraryMainThread!\n" );
	}

	CloseHandle( hProcess );

	return bResult;
}

int main(int argc, CHAR* argv[])
{
	printf( "D_DllLoader coded by s0beit -> SUCH A COOL GUY\n" );

	if( GetDebugPrivileges() == FALSE )
	{
		printf( "WARNING: Unable to get debug privledges...\n" );
	}

	if(argc != 3)
	{
		printf( "Usage: D_DllLoader.exe <process name> <module>\n" );

		printf("Press any key to continue...\n");

		_getch();

		return 0;
	}

	printf( "Targetting [%s] with [%s]\n", argv[1], argv[2] );

	if( AttemptInjection( argv[1], argv[2] ) == FALSE )
	{
		printf( "Injected FAILURE!\n" );
	}
	else
	{
		printf( "Injected success!\n" );
	}

	printf("Press any key to continue...\n");

	_getch();

	return 0;
}

bool SetPrivilege( HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege )
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if(!LookupPrivilegeValue( NULL, lpszPrivilege, &luid )) 
		return false;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);
	
	if (GetLastError() != ERROR_SUCCESS) 
		return false;

	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;
	
	if (bEnablePrivilege) 
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	else
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);

	AdjustTokenPrivileges( hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL );
	
	if( GetLastError() != ERROR_SUCCESS )
		return false;

	return true;
}

BOOL GetDebugPrivileges( void )
{
	HANDLE hToken;

	bool bOK = false;

	if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
	{
		if( !SetPrivilege( hToken, SE_DEBUG_NAME, TRUE ) )
		{
			printf( "GetDebugPrivileges: SetPrivilege error\n" );
		}
		else
		{
			bOK = true;
		}

		CloseHandle( hToken );
	}
	else
	{
		printf( "GetDebugPrivileges: OpenProcessToken error\n" );
	}

	return bOK;
}