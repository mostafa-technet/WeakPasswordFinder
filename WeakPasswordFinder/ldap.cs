using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Windows.Forms;
using System.Data;

namespace WeakPasswordFinder
{
    public partial class Form1
    {

        private void AuthUser()
        {


            try
            {
                string Uid = textBox4.Text;
                string Pass = textBox2.Text;
                if (Uid == "")
                {
                    MessageBox.Show("Username cannot be null");
                }
                else if (Pass == "")
                {
                    MessageBox.Show("Password cannot be null");
                }
                else
                {
                    /*LdapConnection connection = new LdapConnection(textBox1.Text);
                    NetworkCredential credential = new NetworkCredential(Uid, Pass);
                    connection.Credential = credential;
                    connection.Bind();

                    // after authenticate Loading user details to data table
                    PrincipalContext ctx = new PrincipalContext(ContextType.Domain);
                    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, Uid);*/
                    DirectoryEntry up_User = new DirectoryEntry("LDAP://"+textBox1.Text, textBox4.Text, textBox2.Text);//(DirectoryEntry)user.GetUnderlyingObject();
                    up_User.AuthenticationType = AuthenticationTypes.Secure;
                    DirectorySearcher deSearch = new DirectorySearcher(up_User);
                    SearchResultCollection results = deSearch.FindAll();
                    ResultPropertyCollection rpc = results[0].Properties;
                    DataTable dt = new DataTable();
                    DataRow toInsert = dt.NewRow();
                    dt.Rows.InsertAt(toInsert, 0);

                    foreach (string rp in rpc.PropertyNames)
                    {
                        if (rpc[rp][0].ToString() != "System.Byte[]")
                        {
                            dt.Columns.Add(rp.ToString(), typeof(System.String));

                            foreach (DataRow row in dt.Rows)
                            {
                                row[rp.ToString()] = rpc[rp][0].ToString();
                            }

                        }
                    }
                    //You can load data to grid view and see for reference only
                    dataGridView1.DataSource = dt;


                }
            } //Error Handling part
            catch (LdapException lexc)
            {
                String error = lexc.ServerErrorMessage;
                string pp = error.Substring(76, 4);
                string ppp = pp.Trim();

                if ("52e" == ppp)
                {
                    MessageBox.Show("Invalid Username or password, contact Webroam Co");
                }
                if ("775​" == ppp)
                {
                    MessageBox.Show("User account locked, contact Webroam Co");
                }
                if ("525​" == ppp)
                {
                    MessageBox.Show("User not found, contact Webroam Co");
                }
                if ("530" == ppp)
                {
                    MessageBox.Show("Not permitted to logon at this time, contact Webroam Co");
                }
                if ("531" == ppp)
                {
                    MessageBox.Show("Not permitted to logon at this workstation, contact Webroam Co");
                }
                if ("532" == ppp)
                {
                    MessageBox.Show("Password expired, contact Webroam Co");
                }
                if ("533​" == ppp)
                {
                    MessageBox.Show("Account disabled, contact Webroam Co");
                }
                if ("533​" == ppp)
                {
                    MessageBox.Show("Account disabled, contact Webroam Co");
                }



            } //common error handling
            catch (Exception exc)
            {
                MessageBox.Show("Invalid Username or password, contact Webroam Co");

            }

            finally
            {
          //      textBox4.Text = "";
             //   textBox2.Text = "";

            }
        }
    }
}