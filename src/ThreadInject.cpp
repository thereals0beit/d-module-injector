#include "stdafx.h"
#include "ThreadInject.h"

namespace threadInject
{
	DWORD GetPrimaryThreadId( unsigned long ProcessId ) 
	{ 
		HANDLE hSnapThread = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, ProcessId ); 

		if( hSnapThread == INVALID_HANDLE_VALUE ) 
		{ 
			return NULL; 
		} 

		ULONGLONG ullMinCreateTime = MAXULONGLONG;

		DWORD dwMainThreadId = 0;

		THREADENTRY32 te; 

		te.dwSize = sizeof( THREADENTRY32 ); 

		for (BOOL bOK = Thread32First(hSnapThread, &te); bOK; bOK = Thread32Next(hSnapThread, &te)) 
		{
			// Make sure it's what we're looking for (Primary process threads)
			if( ProcessId != te.th32OwnerProcessID )
				continue;

			HANDLE hCurrentThread = OpenThread( THREAD_QUERY_INFORMATION, TRUE, te.th32ThreadID );

			if( hCurrentThread == INVALID_HANDLE_VALUE )
				continue;
			
			FILETIME f[4] = { 0 };

			// Get the lowest possible creation time
			if( GetThreadTimes( hCurrentThread, &f[0], &f[1], &f[2], &f[3] ) == FALSE )
			{
				CloseHandle( hCurrentThread );

				continue;
			}

			ULARGE_INTEGER uliTmp;
			uliTmp.HighPart = f[0].dwHighDateTime;
			uliTmp.LowPart = f[0].dwLowDateTime;

			if ( uliTmp.QuadPart && uliTmp.QuadPart < ullMinCreateTime )
			{
				ullMinCreateTime = uliTmp.QuadPart;

				dwMainThreadId = te.th32ThreadID;
			}

			CloseHandle( hCurrentThread );
		}

		CloseHandle( hSnapThread ); 

		if( ullMinCreateTime == MAXULONGLONG || dwMainThreadId == 0 )
		{
			return NULL;
		}

		return dwMainThreadId;
	} 

	BOOL LoadLibraryMainThread( HANDLE hProcess, char *pszLibraryPath )
	{
		DWORD dwMainThreadId = GetPrimaryThreadId( GetProcessId( hProcess ) );

		if( dwMainThreadId == NULL )
		{
			printf( "Invalid Thread Id\n" );

			return FALSE;
		}

		printf( "Thread Id [0x%X]\n", dwMainThreadId );

		HANDLE hThread = OpenThread( ( THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT ), FALSE, dwMainThreadId );

		if( hThread == INVALID_HANDLE_VALUE )
		{
			printf( "Failed to open thread!\n" );

			return FALSE;
		}

		FARPROC fpLoadLibraryARemote = Remote::GetRemoteProcAddress( hProcess, "Kernel32.dll", "LoadLibraryA" ); 

		if( fpLoadLibraryARemote == NULL )
		{
			CloseHandle( hThread );

			printf( "Failed to find LoadLibraryA address!\n" );

			return FALSE;
		}

		LPVOID lpCommitLibraryName = Remote::Allocate::Commit( hProcess, pszLibraryPath, strlen( pszLibraryPath ) + 1 );

		if( lpCommitLibraryName == NULL )
		{
			CloseHandle( hThread );

			printf( "Failed to commit filename stub!\n" );

			return FALSE;
		}

		printf( "LoadLibraryA [0x%X]\n", fpLoadLibraryARemote );

		unsigned char loadLibraryBuffer[18] = 
		{
			0x68, 0x00, 0x00, 0x00, 0x00,		//push lib name 
			0xB8, 0x00, 0x00, 0x00, 0x00,		//mov eax, LoadLibraryA 
			0xFF, 0xD0,							//call eax 
			0x68, 0x00, 0x00, 0x00, 0x00,		//push (jmp)
			0xC3,								//ret
		};

		SuspendThread( hThread );

		CONTEXT context;

		context.ContextFlags = CONTEXT_CONTROL;

		if( GetThreadContext( hThread, &context ) == FALSE )
		{
			CloseHandle( hThread );

			printf( "Failed to get thread context! (0x%X)\n", GetLastError() );

			Remote::Allocate::Free( hProcess, lpCommitLibraryName, strlen( pszLibraryPath ) + 1 );

			return FALSE;
		}

		*( DWORD* )( loadLibraryBuffer + 0x01 ) = ( DWORD ) lpCommitLibraryName;
		*( DWORD* )( loadLibraryBuffer + 0x06 ) = ( DWORD ) fpLoadLibraryARemote;
		*( DWORD* )( loadLibraryBuffer + 0x0D ) = context.Eip;

		LPVOID lpCodeCave = Remote::Allocate::Commit( hProcess, loadLibraryBuffer, sizeof( loadLibraryBuffer ) );

		if( lpCodeCave != NULL ) 
		{
			context.Eip = ( DWORD ) lpCodeCave;

			if( SetThreadContext( hThread, &context ) == FALSE )
			{
				printf( "Failed to set thread context!\n" );
			}

			Remote::Allocate::Free( hProcess, lpCodeCave, sizeof( loadLibraryBuffer ) );
		}
		else
		{
			printf( "Failed to commit code stub!\n" );
		}

		Remote::Allocate::Free( hProcess, lpCommitLibraryName, strlen( pszLibraryPath ) + 1 );

		ResumeThread( hThread );

		CloseHandle( hThread );

		return TRUE;
	}
};