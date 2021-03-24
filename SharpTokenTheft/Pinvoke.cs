using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpTokenTheft {

	
	public class Pinvoke {


		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern bool PrivilegeCheck( IntPtr ClientToken, ref PRIVILEGE_SET RequiredPrivileges, out bool pfResult);

		[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
		public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref PTOKEN_PRIVILEGES newst, int len, IntPtr prev, IntPtr relen);

		[DllImport("kernel32.dll", ExactSpelling = true)]
		public static extern IntPtr GetCurrentProcess();

		[DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
		public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		public struct PTOKEN_PRIVILEGES {
			public int Count;
			public long Luid;
			public int Attr;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct LUID_AND_ATTRIBUTES {
			public long Luid;
			public UInt32 Attributes;
			public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
			public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
			public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
			public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
		}

		[StructLayout(LayoutKind.Sequential)]
        public struct PRIVILEGE_SET {
			public uint PrivilegeCount;
			public uint Control; 
			public static uint PRIVILEGE_SET_ALL_NECESSARY = 1;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
			public LUID_AND_ATTRIBUTES[] Privilege;
		}
		
		public static int SE_PRIVILEGE_DISABLED = 0x00000000;
		public static int SE_PRIVILEGE_ENABLED = 0x00000002;
		public static int TOKEN_QUERY = 0x00000008;
		public static int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
		public static int TOKEN_DUPLICATE = 0x00000002;
		public static int TOKEN_IMPERSONATE = 0x00000004;
		public static int TOKEN_ASSIGN_PRIMARY = 0x00000001;
		public static int TOKEN_ADJUST_SESSIONID = (0x0100);
		public static int TOKEN_ADJUST_DEFAULT = (0x0080);


		[Flags]
		public enum ProcessAccessFlags : uint {
			All = 0x001F0FFF,
			Terminate = 0x00000001,
			CreateThread = 0x00000002,
			VirtualMemoryOperation = 0x00000008,
			VirtualMemoryRead = 0x00000010,
			VirtualMemoryWrite = 0x00000020,
			DuplicateHandle = 0x00000040,
			CreateProcess = 0x000000080,
			SetQuota = 0x00000100,
			SetInformation = 0x00000200,
			QueryInformation = 0x00000400,
			QueryLimitedInformation = 0x00001000,
			Synchronize = 0x00100000
		}
		public enum TOKEN_TYPE {
			TokenPrimary = 1,
			TokenImpersonation
		}

		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool RevertToSelf();

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess,bool bInheritHandle,int processId);

		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public extern static bool DuplicateTokenEx( IntPtr hExistingToken, int dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool SetThreadToken(IntPtr pHandle, IntPtr hToken);

		[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
		public static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct STARTUPINFO {
			public Int32 cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
			public Int32 dwX;
			public Int32 dwY;
			public Int32 dwXSize;
			public Int32 dwYSize;
			public Int32 dwXCountChars;
			public Int32 dwYCountChars;
			public Int32 dwFillAttribute;
			public Int32 dwFlags;
			public Int16 wShowWindow;
			public Int16 cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct SECURITY_ATTRIBUTES {
			public int nLength;
			public unsafe byte* lpSecurityDescriptor;
			public int bInheritHandle;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct PROCESS_INFORMATION {
			public IntPtr hProcess;
			public IntPtr hThread;
			public int dwProcessId;
			public int dwThreadId;
		}

		public enum TOKEN_INFORMATION_CLASS {
			TokenUser = 1, TokenGroups, TokenPrivileges, TokenOwner, TokenPrimaryGroup, TokenDefaultDacl, TokenSource, TokenType, TokenImpersonationLevel, TokenStatistics, TokenRestrictedSids, TokenSessionId, TokenGroupsAndPrivileges, TokenSessionReference, TokenSandBoxInert, TokenAuditPolicy, TokenOrigin, TokenElevationType, TokenLinkedToken, TokenElevation, TokenHasRestrictions, TokenAccessInformation, TokenVirtualizationAllowed, TokenVirtualizationEnabled,
			TokenIntegrityLevel,
			TokenUIAccess, TokenMandatoryPolicy, TokenLogonSid, MaxTokenInfoClass
		}

		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool GetTokenInformation( IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);


	}
}
