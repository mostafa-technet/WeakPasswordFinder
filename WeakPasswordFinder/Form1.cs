using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Threading;
using IWshRuntimeLibrary;
//using System.ComponentModel;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;
using System.Security.Principal;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using DSInternals.Replication;
using DSInternals.Common.Data;

namespace WeakPasswordFinder
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }


     

        private async void button1_Click(object sender, EventArgs e)
        {
            if(String.IsNullOrWhiteSpace(textBox1.Text))
            {
                MessageBox.Show("Please enter a domain name.");
                return;
            }
            if (String.IsNullOrWhiteSpace(textBox3.Text))
            {
                MessageBox.Show("Please enter a domain controller.");
                return;
            }
            if (String.IsNullOrWhiteSpace(textBox2.Text)|| String.IsNullOrWhiteSpace(textBox4.Text))
            {
                MessageBox.Show("Please enter a valid user name and password.");
                return;
            }
            Total = 0;
            Weak = 0;
            string conS = "DC=" + textBox1.Text;
            if (textBox1.Text.Contains("."))
            {
                var spl = textBox1.Text.Split('.');
                conS = $"DC={spl[0]},DC={spl[1]}";
            }
                try
                {
                    button1.Enabled = false;
                    button3.Enabled = false;
                    Thread[] trds = new Thread[4];
                   // var list1 = GetPermutations<int>(Enumerable.Range(0, trds.Length), trds.Length);
                    //for(int k=0;k<trds.Length;k++)
                    //MessageBox.Show(String.Join<int>(",", list1.ElementAt(k)).ToString());
                    List<KeyValuePair<string, byte[]>>[] lacc = new List<KeyValuePair<string, byte[]>>[trds.Length];
                    List<string> lacc2 = new List<string>();
                   
                    int j = 0;
                    DirectoryReplicationClient client = new DirectoryReplicationClient(textBox1.Text, RpcProtocol.TCP, new NetworkCredential(textBox4.Text, textBox2.Text));
                    IEnumerable<DSAccount> accs = null;
                    this.Text += " - Fetching...";
                    int p = 0;
                    // var PWDS = File.ReadAllLines("PasswordPatterns.txt", Encoding.UTF8);

                    List<byte[]> hashes = new List<byte[]>(100000);
                    await Task.Run(async () =>
                      {
                          accs = client.GetAccounts(conS);
                          DirectoryEntry up_User = new DirectoryEntry("LDAP://" + textBox1.Text, textBox4.Text, textBox2.Text);//(DirectoryEntry)user.GetUnderlyingObject();
                         up_User.AuthenticationType = AuthenticationTypes.Secure;
                          DirectorySearcher deSearch = new DirectorySearcher(up_User);
                          deSearch.PageSize = 10;
                          var results = deSearch.FindAll().AsParallel();
                          Text = Text.Replace("Fetching", "Checking");
                          var pcontext = new PrincipalContext(ContextType.Domain, textBox1.Text, textBox4.Text, textBox2.Text);
                          //int kh = 0;
                          BinaryReader reader = new BinaryReader(new FileStream("pwdcomm.dat", FileMode.Open));

                          try
                          {
                            
                              while (true)
                              {
                                  byte[] buffer = reader.ReadBytes(16);
                                  if (buffer.Length < 16)
                                      break;
                                  hashes.Add(buffer);
                                  
                              }
                              reader.Close();
                          }
                          catch(Exception em)
                          {
                              MessageBox.Show(em.ToString());
                          }
                        //  MessageBox.Show(hashes.Count.ToString());
                          foreach (var a in accs.AsParallel())
                          {
                              if (a != null)
                              {
                                  await Task.Run(() =>
                                 {

                                 byte[] s = a.NTHash;
                                 if (s != null)
                                     foreach (var h in hashes.AsParallel())
                                     {
                                         if (s.SequenceEqual(h))
                                         {
                                             //   isValid = true;
                                             lock (lk2)
                                             {
                                                 Weak++;
                                                 //lacc2.Add(ac.Key);
                                                 label7.Text = Weak.ToString();
                                                 //MessageBox.Show(a.UserPrincipalName);
                                                 //  MessageBox.Show(results[0].Properties["userPrincipalName"][0].ToString());
                                                 //var query = results.Cast<SearchResult>().Where(res => res.GetDirectoryEntry().Properties["userPrincipalName"].Cast<string>().Any(addr => addr == a.UserPrincipalName.Split('@')[0]));

                                                 string dep = "";
                                                 string expiry = "";
                                                 string passRQ = "";
                                                 string aclkd = "";
                                                 string acex = "";
                                                     try
                                                     {
                                                         foreach (SearchResult q in results.AsParallel())
                                                         {

                                                             if (q.Properties["userPrincipalName"].Count > 0)
                                                             {

                                                                 if (q.Properties["userPrincipalName"][0].ToString() == a.UserPrincipalName)//.Split('@')[0])
                                                                 {
                                                                     if (q.Properties["department"].Count > 0)
                                                                         dep = q.Properties["department"][0].ToString();
                                                                     else
                                                                         dep = "DEPARTMENT";

                                                                     bool pNeverAcExpire = false;
                                                                   //  MessageBox.Show(q.GetDirectoryEntry().Properties["userAccountControl"].Value.ToString());
                                                                     if (q.GetDirectoryEntry().Properties["userAccountControl"].Value != null)
                                                                     {
                                                                         pNeverAcExpire = (long.Parse(q.GetDirectoryEntry().Properties["userAccountControl"].Value.ToString())& 0x10000) !=0;
                                                                     }
                                                                
                                                                     /*if (q.Properties["accountExpires"].Count > 0)
                                                                         MessageBox.Show(q.Properties["accountExpires"][0].ToString());
                                                                             acex = DateTime.FromFileTime(long.Parse(q.Properties["accountExpires"][0].ToString())).ToString();*/

                                                                     //        Task.Run(() =>
                                                                     //      {
                                                                     UserPrincipal up = UserPrincipal.FindByIdentity(pcontext, q.Properties["userPrincipalName"][0].ToString());
                                                                     passRQ = up.PasswordNotRequired.ToString();
                                                                     aclkd = up.IsAccountLockedOut() ? "Locked" : "Unlocked";
                                                                     
                                                                     if (pNeverAcExpire||up.PasswordNeverExpires)
                                                                     {
                                                                         expiry = "Never Expires";
                                                                     }
                                                                     else
                                                                     {
                                                                         expiry = q.GetDirectoryEntry().InvokeGet("PasswordExpirationDate").ToString();
                                                                     }
                                                                 if (q.GetDirectoryEntry().Properties["accountExpires"].Count>0)
                                                                 {
                                                                       //  MessageBox.Show(q.Properties["accountExpires"][0].ToString());
                                                                         if (long.Parse(q.Properties["accountExpires"][0].ToString()) < long.MaxValue)
                                                                         {
                                                                             DateTime acd = DateTime.FromFileTime(long.Parse(q.Properties["accountExpires"][0].ToString()));
                                                                             acex = acd.ToLocalTime().ToString();
                                                                         }
                                                                         else
                                                                             acex = "Never Expires";
                                                                     }
                                                                     dataGridView1.Invoke(new Action(() => dataGridView1.Rows.Add(a.LogonName, a.UserPrincipalName, dep, a.DistinguishedName, aclkd, expiry, passRQ, acex)));
                                                                     //    });
                                                                     //MessageBox.Show(passRQ);

                                                                     break;
                                                                 }
                                                             }

                                                         }
                                                     }
                                                     catch (Exception em) { MessageBox.Show("Some error occured!"); }
                                                     //MessageBox.Show(dep);

                                                 }

                                                //           MessageBox.Show(Weak.ToString());
                                                break;
                                             }
                                         }
                                 }
                                 );
                                  lock (lk)
                                  {
                                      Total++;
                                      label9.Text = Total.ToString();
                                  }
                              }
                          }
                      }).ContinueWith((t) => { Text = Text.Replace(" - Checking...", ""); MessageBox.Show("Active Directory Vulnerable Password Scan Successfully Finished."); }); ;
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Your information is invalid. Please correct them and try again.");
                    //MessageBox.Show(ex.ToString());
                }

                button1.Enabled = true;
                button3.Enabled = true;
            
        }
        object lk = new object();
        object lk2 = new object();
        int Total = 0, Weak = 0;

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            new AboutUs().ShowDialog();
        }

        private void closeToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            var lines = System.IO.File.ReadAllLines("PasswordPatterns.txt");
            byte[] hashes = new byte[16];
            //int kh = 0;  
            BinaryWriter writer = new BinaryWriter(new FileStream("pwdcomm.dat", FileMode.Open));
            foreach (var pwd in lines.AsParallel())
            {
                hashes = DSInternals.Common.Cryptography.NTHash.ComputeHash(pwd);
                writer.Write(hashes);                
            }
            writer.Flush();
            writer.Close();
            MessageBox.Show("Success!");
        }

        private void textBox2_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
                button1_Click(null, null);
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            Environment.Exit(0);
        }
        
        private void Form1_Load(object sender, EventArgs e)
        {
            if(!System.IO.File.Exists("FirstRun"))
            {
                Directory.CreateDirectory("C:\\MadacoPassCheck\\");
                foreach (var f in Directory.GetFiles(".").AsParallel())
                {
                    try
                    {
                        System.IO.File.Copy(f, Path.Combine("C:\\MadacoPassCheck\\", Path.GetFileName(f)), true);
                    }
                    catch
                    {
                    }
                }
                if(MessageBox.Show("This is the first run. Do you want to create Desktop shortcut of the Program?", "First Run", MessageBoxButtons.YesNo) == DialogResult.Yes)
                {
                    XShortCut.Create(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), Path.GetFileName(Application.ExecutablePath)+".lnk"), "C:\\MadacoPassCheck\\MadacoPassCheck.exe", "C:\\MadacoPassCheck\\", "MadacoPassCheck");
                }
                System.IO.File.Create("C:\\MadacoPassCheck\\FirstRun");
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (dataGridView1.Rows.Count > 0)
            {
                var sb = new StringBuilder();

                var headers = dataGridView1.Columns.Cast<DataGridViewColumn>();
                sb.AppendLine(string.Join(",", headers.Select(column => "\"" + column.HeaderText + "\"").ToArray()));

                foreach (DataGridViewRow row in dataGridView1.Rows)
                {
                    var cells = row.Cells.Cast<DataGridViewCell>();
                    sb.AppendLine(string.Join(",", cells.Select(cell => "\"" + cell.Value + "\"").ToArray()));
                }
                var osf = new SaveFileDialog();
                osf.Filter = "*.csv|*.csv";
                osf.FileName = textBox1.Text + "_ADVulnerablePasswordsReport.csv";
                if (osf.ShowDialog() != DialogResult.Cancel)
                {
                    System.IO.File.WriteAllText(osf.FileName, sb.ToString());
                }
                MessageBox.Show("Exported to csv Successfully.");
            }
        }
    }

        public static class XShortCut
        {
            /// <summary>
            /// Creates a shortcut in the startup folder from a exe as found in the current directory.
            /// </summary>
            /// <param name="exeName">The exe name e.g. test.exe as found in the current directory</param>
            /// <param name="startIn">The shortcut's "Start In" folder</param>
            /// <param name="description">The shortcut's description</param>
            /// <returns>The folder path where created</returns>
            public static string CreateShortCutInStartUpFolder(string exeName, string startIn, string description)
            {
                var startupFolderPath = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                var linkPath = startupFolderPath + @"\" + exeName + "-Shortcut.lnk";
                var targetPath = Environment.CurrentDirectory + @"\" + exeName;
                System.IO.File.Delete(linkPath);
                Create(linkPath, targetPath, startIn, description);
                return startupFolderPath;
            }

            /// <summary>
            /// Create a shortcut
            /// </summary>
            /// <param name="fullPathToLink">the full path to the shortcut to be created</param>
            /// <param name="fullPathToTargetExe">the full path to the exe to 'really execute'</param>
            /// <param name="startIn">Start in this folder</param>
            /// <param name="description">Description for the link</param>
            public static void Create(string fullPathToLink, string fullPathToTargetExe, string startIn, string description)
            {
                var shell = new WshShell();
                var link = (IWshShortcut)shell.CreateShortcut(fullPathToLink);
                link.IconLocation = fullPathToTargetExe;
                link.TargetPath = fullPathToTargetExe;
                link.Description = description;
                link.WorkingDirectory = startIn;
                link.Save();
            }
        }
    }


