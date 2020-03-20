﻿using System;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using VanillaRat.Classes;

namespace VanillaRat.Forms
{
    public partial class ClientRunningApps : Form
    {
        public ClientRunningApps()
        {
            InitializeComponent();
            MinimizeBox = false;
            MaximizeBox = false;
            Update = true;
        }

        public bool Update { get; set; }

        public int ConnectionID { get; set; }

        //Refresh listed processes
        private void btnRefreshProcesses_Click(object sender, EventArgs e)
        {
            Server.MainServer.Send(ConnectionID, Encoding.ASCII.GetBytes("GetProcesses"));
        }

        //End selected process
        private async void btnEndProcess_Click(object sender, EventArgs e)
        {
            if (lbRunningProcesses.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a process!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            ListViewItem Item = lbRunningProcesses.SelectedItems[0];
            Server.MainServer.Send(ConnectionID,
                Encoding.ASCII.GetBytes("EndProcess<{" + Item.SubItems[1].Text + "}>"));
            await Task.Delay(50);
            Item.Remove();
            Server.MainServer.Send(ConnectionID, Encoding.ASCII.GetBytes("GetProcesses"));
        }

        //On form close
        private void ClientRunningApps_FormClosing(object sender, FormClosingEventArgs e)
        {
            Update = false;
        }

        private void lbRunningProcesses_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }
}