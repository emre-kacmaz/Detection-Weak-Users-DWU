using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace BreachedPasswords_v._1._2
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("--------------------------------------");
            Console.WriteLine("--------------------------------------");
            Console.WriteLine("**************************************");
            Console.WriteLine("**<<<Detection Weak User Accounts>>>**");
            Console.WriteLine("**************************************");
            Console.WriteLine("-------<<<Developed by Kacmaz>>>------");
            Console.WriteLine("---------------------------------------\n");
            Console.WriteLine("Which group do you check?(For all press 1)");
            
            string targetGroup = Console.ReadLine();
            if (targetGroup=="1")
            {
                targetGroup = "Domain Users";
            }
            Console.WriteLine("What is your domain FQDN? (mydomain.local)");
            string domainName = Console.ReadLine();
            string _groupMembers = RunCmdComand("'" + targetGroup + "'");
            string[] groupMembers = _groupMembers.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 2; i < groupMembers.Length; i++)
            {
                GetListNtlmHash(groupMembers[i].ToString(), RunMimikatz(groupMembers[i].ToString(),domainName));
                
            }
            Console.WriteLine("THE END ...");
            Console.ReadKey();
        }
        public static string RunCmdComand(string targetGroup)//Getting Group Members from Active Directory
        {
            Process cmd = new Process();
            cmd.StartInfo.FileName = @"powershell.exe";
            cmd.StartInfo.Arguments = "Get-ADGroupMember -Identity " + targetGroup + " | Select-object SamAccountName | Sort-Object SamAccountName";
            cmd.StartInfo.UseShellExecute = false;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.RedirectStandardError = true;
            cmd.StartInfo.Verb = "runas";
            cmd.Start();
            string groupMembers = cmd.StandardOutput.ReadToEnd();
            return groupMembers;

        }
        public static string RunMimikatz(string user,string domain)//Running Mimikatz
        {
            
            Process process = new Process();
            process.StartInfo.FileName = "mimikatz.exe";
            process.StartInfo.Arguments = "privilege::debug ";
            process.StartInfo.Arguments += "\"lsadump::dcsync /domain:"+domain+" /user:" + user + " \" exit";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            var regex = new Regex(@"Hash\sNTLM\:\s(\S+)\s+");//parsing cmd outputs
            Match m = regex.Match(output);
            if (m.Success)
            {

                output = m.Value;
                output = output.Replace("Hash NTLM:", "");
                output = output.Trim();
            }
            return output;
        }
        public static void GetListNtlmHash(string userName, string userPasswordHash)//Checking with rockyou wordlist
        {
            string[] lines = File.ReadAllLines("rockyou.txt");
            string hash;
            userPasswordHash = userPasswordHash.ToLower();
            for (int i = 0; i < lines.Length; i++)
            {
                hash = Ntlm(lines[i]).ToLower();
                if (userPasswordHash == hash)
                {
                    Console.WriteLine("\nBreached Password Detected ---> " + userName);
                }

            }
        }
        public static string Ntlm(string key)
        {
            const uint INIT_A = 0x67452301;
            const uint INIT_B = 0xefcdab89;
            const uint INIT_C = 0x98badcfe;
            const uint INIT_D = 0x10325476;

            const uint SQRT_2 = 0x5a827999;
            const uint SQRT_3 = 0x6ed9eba1;

            char[] itoa16 = new[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

            uint[] nt_buffer = new uint[16];
            uint[] output = new uint[4];
            char[] hex_format = new char[32];

            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // Prepare the string for hash calculation
            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            int i = 0;
            int length = key.Length;
            //The length of key need to be <= 27
            for (; i < length / 2; i++)
            {
                nt_buffer[i] = (key[2 * i] | ((uint)key[2 * i + 1] << 16));
            }

            //padding
            if (length % 2 == 1)
            {
                nt_buffer[i] = (uint)key[length - 1] | 0x800000;
            }
            else
            {
                nt_buffer[i] = 0x80;
            }

            //put the length
            nt_buffer[14] = (uint)length << 4;

            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // NTLM hash calculation
            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            uint a = INIT_A;
            uint b = INIT_B;
            uint c = INIT_C;
            uint d = INIT_D;

            /* Round 1 */
            a += (d ^ (b & (c ^ d))) + nt_buffer[0]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[1]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[2]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[3]; b = (b << 19) | (b >> 13);

            a += (d ^ (b & (c ^ d))) + nt_buffer[4]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[5]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[6]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[7]; b = (b << 19) | (b >> 13);

            a += (d ^ (b & (c ^ d))) + nt_buffer[8]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[9]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[10]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[11]; b = (b << 19) | (b >> 13);

            a += (d ^ (b & (c ^ d))) + nt_buffer[12]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[13]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[14]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[15]; b = (b << 19) | (b >> 13);

            /* Round 2 */
            a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2; b = (b << 13) | (b >> 19);

            a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2; b = (b << 13) | (b >> 19);

            a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2; b = (b << 13) | (b >> 19);

            a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2; b = (b << 13) | (b >> 19);

            /* Round 3 */
            a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3; b = (b << 15) | (b >> 17);

            a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3; b = (b << 15) | (b >> 17);

            a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3; b = (b << 15) | (b >> 17);

            a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3; b = (b << 15) | (b >> 17);

            output[0] = a + INIT_A;
            output[1] = b + INIT_B;
            output[2] = c + INIT_C;
            output[3] = d + INIT_D;

            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // Convert the hash to hex (for being readable)
            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            for (i = 0; i < 4; i++)
            {
                int j = 0;
                uint n = output[i];
                //iterate the bytes of the integer
                for (; j < 4; j++)
                {
                    uint convert = n % 256;
                    hex_format[i * 8 + j * 2 + 1] = itoa16[convert % 16];
                    convert = convert / 16;
                    hex_format[i * 8 + j * 2 + 0] = itoa16[convert % 16];
                    n = n / 256;
                }
            }

            return string.Join(string.Empty, hex_format);
        }
    }
}
